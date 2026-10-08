use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub ips: Vec<Ipv4Addr>,
    pub expires_at: Instant,
}

pub struct DnsCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    max_entries: usize,
    default_ttl: Duration,
    negative_ttl: Duration,
}

impl DnsCache {
    pub fn new(max_entries: usize, default_ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries,
            default_ttl,
            negative_ttl,
        }
    }

    pub fn get(&self, hostname: &str, port: u16) -> Option<std::io::Result<Vec<SocketAddrV4>>> {
        let key = hostname.to_lowercase();
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.get(&key) {
            if Instant::now() < entry.expires_at {
                if entry.ips.is_empty() {
                    return Some(Err(std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "Cached negative DNS result",
                    )));
                }
                let mapped = entry
                    .ips
                    .iter()
                    .map(|&ip| SocketAddrV4::new(ip, port))
                    .collect();
                return Some(Ok(mapped));
            }
        }
        entries.remove(&key);
        None
    }

    pub fn insert(&self, hostname: &str, result: &std::io::Result<(Vec<Ipv4Addr>, u32)>) {
        let key = hostname.to_lowercase();
        let mut entries = self.entries.lock();

        if entries.len() >= self.max_entries {
            let now = Instant::now();
            let mut expired_keys = Vec::new();
            for (k, entry) in entries.iter() {
                if now >= entry.expires_at {
                    expired_keys.push(k.clone());
                }
            }
            if !expired_keys.is_empty() {
                for k in expired_keys {
                    entries.remove(&k);
                }
            } else if let Some(k) = entries.keys().next().cloned() {
                entries.remove(&k);
            }
        }

        let (ips, ttl) = match result {
            Ok((v, raw_ttl)) => {
                let bounded_ttl = (*raw_ttl).clamp(5, 600) as u64;
                (v.clone(), Duration::from_secs(bounded_ttl))
            }
            Err(_) => (Vec::new(), self.negative_ttl),
        };

        entries.insert(
            key,
            CacheEntry {
                ips,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
    }
}

pub static DIRECT_DNS_CACHE: Lazy<DnsCache> = Lazy::new(|| {
    DnsCache::new(
        1000,
        Duration::from_secs(300),
        Duration::from_secs(10),
    )
});

pub static WARP_DNS_CACHE: Lazy<DnsCache> = Lazy::new(|| {
    DnsCache::new(
        1000,
        Duration::from_secs(300),
        Duration::from_secs(10),
    )
});

pub struct SingleFlight {
    #[allow(clippy::type_complexity)]
    inflight: Mutex<HashMap<String, watch::Receiver<Option<Result<(Vec<Ipv4Addr>, u32), String>>>>>,
}

impl Default for SingleFlight {
    fn default() -> Self {
        Self::new()
    }
}

impl SingleFlight {
    pub fn new() -> Self {
        Self {
            inflight: Mutex::new(HashMap::new()),
        }
    }

    pub async fn execute<F, Fut>(&self, key: &str, lookup: F) -> std::io::Result<(Vec<Ipv4Addr>, u32)>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = std::io::Result<(Vec<Ipv4Addr>, u32)>>,
    {
        let (opt_rx, opt_tx) = {
            let mut inflight = self.inflight.lock();
            if let Some(rx) = inflight.get(key) {
                (Some(rx.clone()), None)
            } else {
                let (tx, rx) = watch::channel(None);
                inflight.insert(key.to_string(), rx.clone());
                (None, Some(tx))
            }
        };

        if let Some(rx) = opt_rx {
            let mut rx = rx;
            loop {
                if let Some(ref val) = *rx.borrow() {
                    return match val {
                        Ok(v) => Ok(v.clone()),
                        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e.clone())),
                    };
                }
                if rx.changed().await.is_err() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "In-flight DNS request coalescing channel closed",
                    ));
                }
            }
        }

        let tx = opt_tx.expect("tx must be present if no rx was cached");
        let res = lookup().await;

        {
            let mut inflight = self.inflight.lock();
            inflight.remove(key);
        }

        let mapped = match &res {
            Ok(v) => Ok(v.clone()),
            Err(e) => Err(e.to_string()),
        };
        let _ = tx.send(Some(mapped));

        res
    }
}

pub static DIRECT_SINGLE_FLIGHT: Lazy<SingleFlight> = Lazy::new(SingleFlight::new);
pub static WARP_SINGLE_FLIGHT: Lazy<SingleFlight> = Lazy::new(SingleFlight::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_positive_cache_ttl_bounds() {
        let cache = DnsCache::new(5, Duration::from_secs(300), Duration::from_secs(10));
        let hostname = "test.google.com";

        cache.insert(hostname, &Ok((vec![Ipv4Addr::new(8, 8, 8, 8)], 1)));

        let res = cache.get(hostname, 80).unwrap().unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].ip(), &std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(res[0].port(), 80);

        cache.insert(hostname, &Ok((vec![Ipv4Addr::new(8, 8, 8, 8)], 1000)));
        let entry = cache.entries.lock().get(&hostname.to_string()).unwrap().clone();
        let duration = entry.expires_at.duration_since(Instant::now());
        assert!(duration.as_secs() > 590 && duration.as_secs() <= 600);
    }

    #[test]
    fn test_negative_cache_and_expiry() {
        let cache = DnsCache::new(5, Duration::from_secs(300), Duration::from_secs(1));
        let hostname = "test-fail.google.com";

        cache.insert(
            hostname,
            &Err(std::io::Error::new(std::io::ErrorKind::NotFound, "err")),
        );
        let res = cache.get(hostname, 80).unwrap();
        assert!(res.is_err());

        std::thread::sleep(Duration::from_millis(1100));
        assert!(cache.get(hostname, 80).is_none());
    }

    #[test]
    fn test_cache_bounds_eviction() {
        let cache = DnsCache::new(3, Duration::from_secs(300), Duration::from_secs(10));
        cache.insert("h1.com", &Ok((vec![Ipv4Addr::new(1, 1, 1, 1)], 60)));
        cache.insert("h2.com", &Ok((vec![Ipv4Addr::new(2, 2, 2, 2)], 60)));
        cache.insert("h3.com", &Ok((vec![Ipv4Addr::new(3, 3, 3, 3)], 60)));

        cache.insert("h4.com", &Ok((vec![Ipv4Addr::new(4, 4, 4, 4)], 60)));

        assert_eq!(cache.entries.lock().len(), 3);
        assert!(cache.get("h4.com", 80).is_some());
    }

    #[test]
    fn test_route_separation() {
        DIRECT_DNS_CACHE.clear();
        WARP_DNS_CACHE.clear();

        let host = "route-test.com";
        DIRECT_DNS_CACHE.insert(host, &Ok((vec![Ipv4Addr::new(1, 1, 1, 1)], 60)));

        assert!(DIRECT_DNS_CACHE.get(host, 80).is_some());
        assert!(WARP_DNS_CACHE.get(host, 80).is_none());
    }

    #[tokio::test]
    async fn test_single_flight_coalescing() {
        let sf = SingleFlight::new();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let sf_ref = Arc::new(sf);
        let mut join_handles = Vec::new();

        for _ in 0..5 {
            let sf_clone = Arc::clone(&sf_ref);
            let counter_clone = Arc::clone(&counter);
            let handle = tokio::spawn(async move {
                sf_clone
                    .execute("test-key", || async {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Ok((vec![Ipv4Addr::new(9, 9, 9, 9)], 300))
                    })
                    .await
            });
            join_handles.push(handle);
        }

        for h in join_handles {
            let res = h.await.unwrap().unwrap();
            assert_eq!(res, (vec![Ipv4Addr::new(9, 9, 9, 9)], 300));
        }

        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
