//! Client IP attribution. The TCP peer is the client unless it is a configured trusted proxy, in which case
//! the client is the right-most `X-Forwarded-For` hop that is not itself a trusted proxy.

use std::net::IpAddr;

use http::HeaderMap;
use ipnet::IpNet;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientIpError {
    #[error("request from trusted proxy {0} carries no X-Forwarded-For header")]
    Missing(IpAddr),
    #[error("X-Forwarded-For is not valid: {0}")]
    Malformed(String),
    #[error("X-Forwarded-For lists only trusted proxies")]
    OnlyProxies,
}

#[derive(Clone, Debug)]
pub struct ClientIpPolicy {
    /// Empty in `acme` mode: the peer is always the client.
    pub trusted_proxies: Vec<IpNet>,
}

impl ClientIpPolicy {
    fn trusted(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        self.trusted_proxies.iter().any(|net| net.contains(&ip))
    }

    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> Result<IpAddr, ClientIpError> {
        let peer = canonical(peer);
        if !self.trusted(peer) {
            return Ok(peer);
        }
        let values: Vec<&http::HeaderValue> = headers.get_all("x-forwarded-for").iter().collect();
        if values.is_empty() {
            return Err(ClientIpError::Missing(peer));
        }
        let mut hops = Vec::new();
        for value in values {
            let text = value.to_str().map_err(|_| ClientIpError::Malformed("non-ASCII header value".into()))?;
            for part in text.split(',') {
                let part = part.trim();
                let ip: IpAddr = part.parse().map_err(|_| ClientIpError::Malformed(format!("`{part}` is not an IP")))?;
                hops.push(canonical(ip));
            }
        }
        hops.into_iter().rev().find(|ip| !self.trusted(*ip)).ok_or(ClientIpError::OnlyProxies)
    }
}

/// IPv4-mapped IPv6 addresses (dual-stack listeners) are treated as the IPv4 address.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ClientIpPolicy {
        ClientIpPolicy { trusted_proxies: vec!["10.0.0.0/8".parse().unwrap()] }
    }

    fn headers(xff: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in xff {
            h.append("x-forwarded-for", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn untrusted_peer_is_the_client_even_with_header() {
        let ip = policy().client_ip("203.0.113.9".parse().unwrap(), &headers(&["198.51.100.1"])).unwrap();
        assert_eq!(ip, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted_hop() {
        let h = headers(&["198.51.100.1, 203.0.113.5", "10.1.2.3"]);
        let ip = policy().client_ip("10.0.0.2".parse().unwrap(), &h).unwrap();
        assert_eq!(ip, "203.0.113.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_peer_without_header_is_an_error() {
        let err = policy().client_ip("10.0.0.2".parse().unwrap(), &HeaderMap::new()).unwrap_err();
        assert!(matches!(err, ClientIpError::Missing(_)));
        let err = policy().client_ip("10.0.0.2".parse().unwrap(), &headers(&["nope"])).unwrap_err();
        assert!(matches!(err, ClientIpError::Malformed(_)));
        let err = policy().client_ip("10.0.0.2".parse().unwrap(), &headers(&["10.9.9.9"])).unwrap_err();
        assert_eq!(err, ClientIpError::OnlyProxies);
    }

    #[test]
    fn mapped_ipv4_peer_matches_ipv4_proxy_range() {
        let h = headers(&["198.51.100.1"]);
        let ip = policy().client_ip("::ffff:10.0.0.2".parse().unwrap(), &h).unwrap();
        assert_eq!(ip, "198.51.100.1".parse::<IpAddr>().unwrap());
    }
}
