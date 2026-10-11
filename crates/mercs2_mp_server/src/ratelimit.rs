//! In-memory per-client-IP token buckets.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use crate::config::BucketConfig;

struct Bucket {
    tokens: f64,
    updated: Instant,
}

pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(cfg: BucketConfig) -> RateLimiter {
        RateLimiter {
            capacity: f64::from(cfg.burst),
            refill_per_sec: f64::from(cfg.refill_per_minute) / 60.0,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one token for `ip`; false when the bucket is empty.
    pub fn check(&self, ip: IpAddr, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().expect("rate limiter mutex poisoned by an earlier panic");
        let bucket = buckets.entry(ip).or_insert(Bucket { tokens: self.capacity, updated: now });
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drops buckets that have refilled completely; they are indistinguishable from absent ones.
    pub fn prune(&self, now: Instant) {
        let mut buckets = self.buckets.lock().expect("rate limiter mutex poisoned by an earlier panic");
        buckets.retain(|_, b| {
            let elapsed = now.saturating_duration_since(b.updated).as_secs_f64();
            b.tokens + elapsed * self.refill_per_sec < self.capacity
        });
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn burst_then_refill() {
        let rl = RateLimiter::new(BucketConfig { burst: 2, refill_per_minute: 60 });
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        let t0 = Instant::now();
        assert!(rl.check(ip, t0));
        assert!(rl.check(ip, t0));
        assert!(!rl.check(ip, t0));
        assert!(rl.check(other, t0), "buckets are per IP");
        assert!(rl.check(ip, t0 + Duration::from_secs(1)), "one token per second refills");
        assert!(!rl.check(ip, t0 + Duration::from_secs(1)));
        rl.prune(t0 + Duration::from_secs(10));
        assert_eq!(rl.len(), 0);
    }
}
