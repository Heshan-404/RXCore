use async_trait::async_trait;
use rand::Rng;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout, Duration};
use uuid::Uuid;

use crate::inbound::InboundTransportStream;
use crate::config::FragmentSettings;
use crate::outbound::OutboundHandler;
use crate::state::EngineState;

pub struct FragmentOutbound {
    pub settings: Option<FragmentSettings>,
}

impl FragmentOutbound {
    pub fn new(settings: Option<FragmentSettings>) -> Self {
        Self { settings }
    }

    fn parse_range(range_str: &str, default_min: usize, default_max: usize) -> (usize, usize) {
        let parts: Vec<&str> = range_str.split('-').collect();
        if parts.len() == 2 {
            let min = parts[0].trim().parse().unwrap_or(default_min);
            let max = parts[1].trim().parse().unwrap_or(default_max);
            (min, max)
        } else {
            (default_min, default_max)
        }
    }
}

#[async_trait]
impl OutboundHandler for FragmentOutbound {
    async fn handle(
        &self,
        inbound_stream: InboundTransportStream,
        dest_addr: &str,
        dest_port: u16,
        rx_counter: Arc<AtomicU64>,
        tx_counter: Arc<AtomicU64>,
        engine_state: &Arc<EngineState>,
        client_email: &Option<String>,
        _conn_id: &Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let resolve_addr = format!("{}:{}", dest_addr, dest_port);
        let dial_fut = TcpStream::connect(&resolve_addr);
        let outbound_stream = match timeout(Duration::from_secs(10), dial_fut).await {
            Ok(conn_res) => conn_res?,
            Err(_) => return Err("Dial destination timed out".into()),
        };

        let _ = outbound_stream.set_nodelay(true);

        let user_stats = engine_state.get_user_stats(client_email);

        // Split streams
        let (mut in_reader, mut in_writer) = tokio::io::split(inbound_stream);
        let (mut out_reader, mut out_writer) = outbound_stream.into_split();

        // Target -> Client (Download)
        let rx_user = user_stats.clone();
        let download_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match out_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if in_writer.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        rx_counter.fetch_add(n as u64, Ordering::Relaxed);
                        if let Some(ref stats) = rx_user {
                            stats.rx.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = in_writer.shutdown().await;
        });

        // Client -> Target (Upload with fragmentation on ClientHello / initial payload)
        let tx_user = user_stats.clone();
        let settings = self.settings.clone();

        let upload_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut is_first_payload = true;

            loop {
                match in_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if is_first_payload && settings.is_some() {
                            is_first_payload = false;
                            let s = settings.as_ref().unwrap();

                            // Fragmentation Strategy
                            // For example: split packet range "1-5" bytes size intervals
                            let (min_packets, max_packets) = Self::parse_range(&s.packets, 1, 5);
                            let (min_len, max_len) = Self::parse_range(&s.length, 1, 10);
                            let interval_ms = s.interval;

                            let mut offset = 0;

                            // Fragment the initial ClientHello bytes block
                            while offset < n {
                                let chunk_size = {
                                    let mut rng = rand::thread_rng();
                                    rng.gen_range(min_len..=max_len).min(n - offset)
                                };
                                if chunk_size == 0 {
                                    break;
                                }

                                if out_writer.write_all(&buf[offset..offset + chunk_size]).await.is_err() {
                                    return;
                                }
                                tx_counter.fetch_add(chunk_size as u64, Ordering::Relaxed);
                                if let Some(ref stats) = tx_user {
                                    stats.tx.fetch_add(chunk_size as u64, Ordering::Relaxed);
                                }
                                offset += chunk_size;

                                // Random packet count check
                                let _packet_splits = {
                                    let mut rng = rand::thread_rng();
                                    rng.gen_range(min_packets..=max_packets)
                                };

                                if offset < n && interval_ms > 0 {
                                    sleep(Duration::from_millis(interval_ms)).await;
                                }
                            }
                        } else {
                            if out_writer.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            tx_counter.fetch_add(n as u64, Ordering::Relaxed);
                            if let Some(ref stats) = tx_user {
                                stats.tx.fetch_add(n as u64, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = out_writer.shutdown().await;
        });

        let _ = tokio::join!(download_task, upload_task);
        Ok(())
    }
}
