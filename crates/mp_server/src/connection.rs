//! One authenticated WebSocket connection: reads requests, writes exactly one reply or error per request id,
//! forwards pushes from the hub, keeps the connection alive, and closes it on session expiry, idleness,
//! protocol violations or when the hub tells it to.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use mp_api::ws::{ClientFrame, ServerFrame};
use mp_api::{ApiError, ErrorCode};
use tokio::sync::{mpsc, watch};

use crate::api::App;
use crate::db::SessionRow;
use crate::hub::{CLOSE_POLICY, Kill};
use crate::util::now_unix;

enum Exit {
    /// Send this close frame, then stop.
    Close(u16, String),
    /// The peer closed or the transport failed; nothing more can be sent.
    Gone,
}

pub async fn run(app: Arc<App>, socket: WebSocket, session: SessionRow) {
    let user = session.user.clone();
    let (push_tx, push_rx) = mpsc::channel(app.websocket.outbound_queue);
    let (kill_tx, kill_rx) = watch::channel(None);
    let conn_id = match app.hub.register(&user, push_tx, kill_tx) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(user = user.user_id.0, error = %e, "could not register connection");
            close(socket, 1011, &e.message).await;
            return;
        }
    };
    tracing::info!(user = user.user_id.0, conn_id, "websocket connected");
    let (socket, exit) = serve(&app, socket, &session, conn_id, push_rx, kill_rx).await;
    if let Exit::Close(code, reason) = exit {
        tracing::info!(user = user.user_id.0, conn_id, code, %reason, "closing websocket");
        close(socket, code, &reason).await;
    }
    if let Err(e) = app.hub.disconnect(user.user_id, conn_id) {
        tracing::error!(user = user.user_id.0, conn_id, error = %e, "disconnect cleanup failed");
    }
    tracing::info!(user = user.user_id.0, conn_id, "websocket disconnected");
}

async fn close(mut socket: WebSocket, code: u16, reason: &str) {
    let frame = CloseFrame { code, reason: reason.into() };
    if let Err(e) = socket.send(Message::Close(Some(frame))).await {
        tracing::debug!(error = %e, "close frame not delivered");
    }
}

async fn send(socket: &mut WebSocket, frame: &ServerFrame) -> Result<(), Exit> {
    let text = serde_json::to_string(frame).expect("server frames always serialize");
    socket.send(Message::text(text)).await.map_err(|e| {
        tracing::debug!(error = %e, "websocket send failed");
        Exit::Gone
    })
}

async fn serve(
    app: &App,
    mut socket: WebSocket,
    session: &SessionRow,
    conn_id: u64,
    mut pushes: mpsc::Receiver<ServerFrame>,
    mut kill: watch::Receiver<Option<Kill>>,
) -> (WebSocket, Exit) {
    // A session that expired since authentication gets a zero-length timer and closes at once.
    let ttl = Duration::from_secs(u64::try_from(session.expires_at - now_unix()).unwrap_or(0));
    let expiry = tokio::time::sleep(ttl);
    tokio::pin!(expiry);
    let mut ping = tokio::time::interval(app.websocket.ping_interval());
    ping.reset();
    let idle_timeout = app.websocket.idle_timeout();
    let mut last_inbound = Instant::now();

    let exit = loop {
        tokio::select! {
            changed = kill.changed() => {
                match changed {
                    Ok(()) => {
                        let k = (*kill.borrow()).expect("kill is only ever set to Some");
                        break Exit::Close(k.code, k.reason.into());
                    }
                    // The hub dropped this connection's handle without a reason; only takeover does that and it
                    // always sets a reason first, so this is the same as being told to close.
                    Err(_) => break Exit::Close(CLOSE_POLICY, "connection released by the server".into()),
                }
            }
            () = &mut expiry => break Exit::Close(CLOSE_POLICY, "session expired".into()),
            _ = ping.tick() => {
                if last_inbound.elapsed() > idle_timeout {
                    break Exit::Close(CLOSE_POLICY, "idle timeout".into());
                }
                if let Err(e) = socket.send(Message::Ping(Default::default())).await {
                    tracing::debug!(error = %e, "websocket ping failed");
                    break Exit::Gone;
                }
            }
            push = pushes.recv() => match push {
                Some(frame) => if let Err(exit) = send(&mut socket, &frame).await { break exit },
                None => break Exit::Close(CLOSE_POLICY, "connection released by the server".into()),
            },
            msg = socket.recv() => {
                last_inbound = Instant::now();
                let msg = match msg {
                    None => break Exit::Gone,
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "websocket receive failed");
                        break Exit::Gone;
                    }
                    Some(Ok(m)) => m,
                };
                match msg {
                    Message::Text(text) => {
                        match request(app, session, conn_id, text.as_str()).await {
                            Ok(frame) => if let Err(exit) = send(&mut socket, &frame).await { break exit },
                            Err(exit) => break exit,
                        }
                    }
                    Message::Binary(_) => break Exit::Close(CLOSE_POLICY, "binary frames are not part of the protocol".into()),
                    Message::Ping(_) | Message::Pong(_) => {}
                    // tungstenite answers the peer's close frame itself.
                    Message::Close(_) => break Exit::Gone,
                }
            }
        }
    };
    (socket, exit)
}

/// Exactly one reply or error for a frame with a readable id; a frame without one closes the connection.
async fn request(app: &App, session: &SessionRow, conn_id: u64, text: &str) -> Result<ServerFrame, Exit> {
    let frame: ClientFrame = match serde_json::from_str(text) {
        Ok(f) => f,
        Err(parse_error) => {
            // Only probing whether the frame carries an id to address the error to; a frame that is not even
            // JSON has none and closes the connection below.
            let id = serde_json::from_str::<serde_json::Value>(text)
                .ok()
                .and_then(|v| v.get("id").and_then(serde_json::Value::as_u64));
            return match id {
                Some(id) => Ok(ServerFrame::Error {
                    id,
                    error: ApiError::new(ErrorCode::Unsupported, format!("unsupported request: {parse_error}")),
                }),
                None => Err(Exit::Close(CLOSE_POLICY, "frame is not a request with a numeric id".into())),
            };
        }
    };
    let id = frame.id;
    Ok(match app.hub.handle(&session.user, conn_id, frame.request).await {
        Ok(response) => ServerFrame::Reply { id, response },
        Err(error) => ServerFrame::Error { id, error },
    })
}
