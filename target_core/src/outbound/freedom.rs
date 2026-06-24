use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::time::timeout;
use uuid::Uuid;

use crate::inbound::InboundTransportStream;
use crate::outbound::OutboundHandler;
use crate::state::EngineState;

pub struct FreedomOutbound {
    outbound_proxy: Option<String>,
    bind_address: Option<String>,
}

impl FreedomOutbound {
    pub fn new(outbound_proxy: Option<String>, bind_address: Option<String>) -> Self {
        Self { outbound_proxy, bind_address }
    }
}

#[async_trait]
impl OutboundHandler for FreedomOutbound {
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
        tracing::info!(proxy = ?self.outbound_proxy, dest = %dest_addr, port = dest_port, "Freedom dialing TCP");
        let dial_fut = crate::transport::dial_tcp(dest_addr, dest_port, &self.bind_address, &self.outbound_proxy);
        let outbound_stream = match timeout(std::time::Duration::from_secs(10), dial_fut).await {
            Ok(conn_res) => conn_res?,
            Err(_) => return Err("Dial destination timed out".into()),
        };

        let _ = outbound_stream.set_nodelay(true);

        let user_stats = engine_state.get_user_stats(client_email);
        let mut inbound_mut = inbound_stream;
        match inbound_mut {
            InboundTransportStream::Plain(ref mut tcp_in) => {
                #[cfg(target_os = "linux")]
                {
                    use std::os::fd::AsRawFd;
                    
                    let in_fd = tcp_in.as_raw_fd();
                    let out_fd = outbound_stream.as_raw_fd();

                    let (pipe1_rd, pipe1_wr) = match nix::unistd::pipe() {
                        Ok(p) => p,
                        Err(e) => return Err(e.into()),
                    };
                    let (pipe2_rd, pipe2_wr) = match nix::unistd::pipe() {
                        Ok(p) => p,
                        Err(e) => return Err(e.into()),
                    };

                    let handle_upload = tokio::task::spawn_blocking(move || {
                        let p1_rd = pipe1_rd.as_raw_fd();
                        let p1_wr = pipe1_wr.as_raw_fd();
                        let mut pipe_len = 0;
                        let mut total_bytes = 0u64;

                        loop {
                            let mut progress = false;

                            if pipe_len < 65536 {
                                match nix::fcntl::splice(
                                    in_fd,
                                    None,
                                    p1_wr,
                                    None,
                                    65536 - pipe_len,
                                    nix::fcntl::SpliceFFlags::SPLICE_F_NONBLOCK | nix::fcntl::SpliceFFlags::SPLICE_F_MOVE,
                                ) {
                                    Ok(n) if n == 0 => break,
                                    Ok(n) => {
                                        pipe_len += n;
                                        progress = true;
                                    }
                                    Err(e) if e == nix::errno::Errno::EAGAIN => {}
                                    Err(_) => break,
                                }
                            }

                            if pipe_len > 0 {
                                match nix::fcntl::splice(
                                    p1_rd,
                                    None,
                                    out_fd,
                                    None,
                                    pipe_len,
                                    nix::fcntl::SpliceFFlags::SPLICE_F_NONBLOCK | nix::fcntl::SpliceFFlags::SPLICE_F_MOVE,
                                ) {
                                    Ok(n) if n == 0 => break,
                                    Ok(n) => {
                                        pipe_len -= n;
                                        total_bytes += n as u64;
                                        progress = true;
                                    }
                                    Err(e) if e == nix::errno::Errno::EAGAIN => {}
                                    Err(_) => break,
                                }
                            }

                            if !progress {
                                std::thread::sleep(std::time::Duration::from_millis(5));
                            }
                        }

                        unsafe {
                            let _ = libc::shutdown(in_fd, libc::SHUT_RD);
                            let _ = libc::shutdown(out_fd, libc::SHUT_WR);
                        }

                        while pipe_len > 0 {
                            match nix::fcntl::splice(
                                p1_rd,
                                None,
                                out_fd,
                                None,
                                pipe_len,
                                nix::fcntl::SpliceFFlags::SPLICE_F_NONBLOCK | nix::fcntl::SpliceFFlags::SPLICE_F_MOVE,
                            ) {
                                Ok(n) if n == 0 => break,
                                Ok(n) => {
                                    pipe_len -= n;
                                    total_bytes += n as u64;
                                }
                                Err(e) if e == nix::errno::Errno::EAGAIN => std::thread::sleep(std::time::Duration::from_millis(2)),
                                Err(_) => break,
                            }
                        }

                        drop(pipe1_rd);
                        drop(pipe1_wr);
                        Ok::<u64, Box<dyn std::error::Error + Send + Sync>>(total_bytes)
                    });

                    let handle_download = tokio::task::spawn_blocking(move || {
                        let p2_rd = pipe2_rd.as_raw_fd();
                        let p2_wr = pipe2_wr.as_raw_fd();
                        let mut pipe_len = 0;
                        let mut total_bytes = 0u64;

                        loop {
                            let mut progress = false;

                            if pipe_len < 65536 {
                                match nix::fcntl::splice(
                                    out_fd,
                                    None,
                                    p2_wr,
                                    None,
                                    65536 - pipe_len,
                                    nix::fcntl::SpliceFFlags::SPLICE_F_NONBLOCK | nix::fcntl::SpliceFFlags::SPLICE_F_MOVE,
                                ) {
                                    Ok(n) if n == 0 => break,
                                    Ok(n) => {
                                        pipe_len += n;
                                        progress = true;
                                    }
                                    Err(e) if e == nix::errno::Errno::EAGAIN => {}
                                    Err(_) => break,
                                }
                            }

                            if pipe_len > 0 {
                                match nix::fcntl::splice(
                                    p2_rd,
                                    None,
                                    in_fd,
                                    None,
                                    pipe_len,
                                    nix::fcntl::SpliceFFlags::SPLICE_F_NONBLOCK | nix::fcntl::SpliceFFlags::SPLICE_F_MOVE,
                                ) {
                                    Ok(n) if n == 0 => break,
                                    Ok(n) => {
                                        pipe_len -= n;
                                        total_bytes += n as u64;
                                        progress = true;
                                    }
                                    Err(e) if e == nix::errno::Errno::EAGAIN => {}
                                    Err(_) => break,
                                }
                            }

                            if !progress {
                                std::thread::sleep(std::time::Duration::from_millis(5));
                            }
                        }

                        unsafe {
                            let _ = libc::shutdown(out_fd, libc::SHUT_RD);
                            let _ = libc::shutdown(in_fd, libc::SHUT_WR);
                        }

                        while pipe_len > 0 {
                            match nix::fcntl::splice(
                                p2_rd,
                                None,
                                in_fd,
                                None,
                                pipe_len,
                                nix::fcntl::SpliceFFlags::SPLICE_F_NONBLOCK | nix::fcntl::SpliceFFlags::SPLICE_F_MOVE,
                            ) {
                                Ok(n) if n == 0 => break,
                                Ok(n) => {
                                    pipe_len -= n;
                                    total_bytes += n as u64;
                                }
                                Err(e) if e == nix::errno::Errno::EAGAIN => std::thread::sleep(std::time::Duration::from_millis(2)),
                                Err(_) => break,
                            }
                        }

                        drop(pipe2_rd);
                        drop(pipe2_wr);
                        Ok::<u64, Box<dyn std::error::Error + Send + Sync>>(total_bytes)
                    });

                    let upload_res = handle_upload.await;
                    let download_res = handle_download.await;

                    let tx_bytes = match upload_res {
                        Ok(Ok(bytes)) => bytes,
                        _ => 0,
                    };
                    let rx_bytes = match download_res {
                        Ok(Ok(bytes)) => bytes,
                        _ => 0,
                    };

                    rx_counter.fetch_add(rx_bytes, std::sync::atomic::Ordering::Relaxed);
                    tx_counter.fetch_add(tx_bytes, std::sync::atomic::Ordering::Relaxed);
                    if let Some(ref stats) = user_stats {
                        stats.rx.fetch_add(rx_bytes, std::sync::atomic::Ordering::Relaxed);
                        stats.tx.fetch_add(tx_bytes, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let mut outbound_mut = outbound_stream;
                    if let Ok((tx_bytes, rx_bytes)) = tokio::io::copy_bidirectional(tcp_in, &mut outbound_mut).await {
                        rx_counter.fetch_add(rx_bytes, std::sync::atomic::Ordering::Relaxed);
                        tx_counter.fetch_add(tx_bytes, std::sync::atomic::Ordering::Relaxed);
                        if let Some(ref stats) = user_stats {
                            stats.rx.fetch_add(rx_bytes, std::sync::atomic::Ordering::Relaxed);
                            stats.tx.fetch_add(tx_bytes, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }
            InboundTransportStream::Tls(mut inbound_tls) => {
                let mut outbound_mut = outbound_stream;
                if let Ok((tx_bytes, rx_bytes)) = tokio::io::copy_bidirectional(&mut inbound_tls, &mut outbound_mut).await {
                    rx_counter.fetch_add(rx_bytes, std::sync::atomic::Ordering::Relaxed);
                    tx_counter.fetch_add(tx_bytes, std::sync::atomic::Ordering::Relaxed);
                    if let Some(ref stats) = user_stats {
                        stats.rx.fetch_add(rx_bytes, std::sync::atomic::Ordering::Relaxed);
                        stats.tx.fetch_add(tx_bytes, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }
        Ok(())
    }
}
