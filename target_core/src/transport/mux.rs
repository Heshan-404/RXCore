use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use bytes::{Bytes, Buf};


pub enum OutboundTransportStream {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl tokio::io::AsyncRead for OutboundTransportStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Self::Tls(ref mut s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for OutboundTransportStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Self::Tls(ref mut s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => std::pin::Pin::new(s).poll_flush(cx),
            Self::Tls(ref mut s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(ref mut s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Self::Tls(ref mut s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub struct MuxFrame {
    pub stream_id: u32,
    pub cmd: u8, // 0 = Data, 1 = Open, 2 = Close
    pub payload: bytes::Bytes,
}

async fn run_connection_writer<W: AsyncWriteExt + Unpin>(
    mut writer: W,
    mut rx_frames: mpsc::Receiver<MuxFrame>,
) -> std::io::Result<()> {
    let mut header_buf = [0u8; 6];
    while let Some(frame) = rx_frames.recv().await {
        let payload_len = frame.payload.len();
        if payload_len > 65535 {
            continue;
        }
        let header = (frame.stream_id & 0x3F_FF_FF_FF) | ((frame.cmd as u32) << 30);
        header_buf[0..4].copy_from_slice(&header.to_be_bytes());
        header_buf[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        writer.write_all(&header_buf).await?;
        if payload_len > 0 {
            writer.write_all(&frame.payload).await?;
        }
    }
    Ok(())
}

async fn run_connection_reader<R: AsyncReadExt + Unpin>(
    mut reader: R,
    active_streams: Arc<parking_lot::Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>,
) -> std::io::Result<()> {
    let mut main_buf = bytes::BytesMut::with_capacity(65536);

    loop {
        while main_buf.len() < 6 {
            if reader.read_buf(&mut main_buf).await? == 0 {
                return Ok(());
            }
        }

        let header = u32::from_be_bytes([main_buf[0], main_buf[1], main_buf[2], main_buf[3]]);
        let payload_len = u16::from_be_bytes([main_buf[4], main_buf[5]]) as usize;
        let cmd = (header >> 30) as u8;
        let stream_id = header & 0x3F_FF_FF_FF;

        let total_frame_len = 6 + payload_len;
        while main_buf.len() < total_frame_len {
            if reader.read_buf(&mut main_buf).await? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Connection truncated while waiting for payload",
                ));
            }
        }

        main_buf.advance(6);
        let payload = main_buf.split_to(payload_len).freeze();

        let streams_guard = active_streams.lock();
        if let Some(tx) = streams_guard.get(&stream_id) {
            match cmd {
                0 => {
                    let _ = tx.try_send(payload);
                }
                2 => {
                    let _ = tx.try_send(Bytes::new());
                }
                _ => {}
            }
        }

        if main_buf.capacity() > 256 * 1024 {
            let mut new_buf = bytes::BytesMut::with_capacity(65536);
            if !main_buf.is_empty() {
                new_buf.extend_from_slice(&main_buf);
            }
            main_buf = new_buf;
        }
    }
}

pub struct OutboundSession {
    pub socket: Arc<tokio::net::UdpSocket>,
    pub handle: tokio::task::JoinHandle<()>,
    pub last_active: Arc<std::sync::atomic::AtomicU64>,
}

pub struct MuxConnection {
    tx_frames: mpsc::Sender<MuxFrame>,
    active_streams: Arc<parking_lot::Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>,
    next_stream_id: Arc<std::sync::atomic::AtomicU32>,
    stream_count: Arc<std::sync::atomic::AtomicU32>,
    writer_handle: tokio::task::JoinHandle<()>,
    reader_handle: tokio::task::JoinHandle<()>,
}

pub struct MuxVirtualStream {
    stream_id: u32,
    tx_frames: tokio_util::sync::PollSender<MuxFrame>,
    rx_data: mpsc::Receiver<Bytes>,
    current_read_chunk: Option<Bytes>,
    conn_stream_count: Arc<std::sync::atomic::AtomicU32>,
    active_streams: Arc<parking_lot::Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>,
}

impl tokio::io::AsyncRead for MuxVirtualStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            if let Some(ref mut chunk) = self.current_read_chunk {
                let to_read = std::cmp::min(chunk.len(), buf.remaining());
                buf.put_slice(&chunk[..to_read]);
                chunk.advance(to_read);
                if chunk.is_empty() {
                    self.current_read_chunk = None;
                }
                return std::task::Poll::Ready(Ok(()));
            }

            match self.rx_data.poll_recv(cx) {
                std::task::Poll::Ready(Some(chunk)) => {
                    if chunk.is_empty() {
                        return std::task::Poll::Ready(Ok(()));
                    }
                    self.current_read_chunk = Some(chunk);
                }
                std::task::Poll::Ready(None) => {
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Pending => {
                    return std::task::Poll::Pending;
                }
            }
        }
    }
}

impl tokio::io::AsyncWrite for MuxVirtualStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.tx_frames.poll_reserve(cx) {
            std::task::Poll::Ready(Ok(())) => {
                let frame = MuxFrame {
                    stream_id: self.stream_id,
                    cmd: 0,
                    payload: Bytes::copy_from_slice(buf),
                };
                if self.tx_frames.send_item(frame).is_err() {
                    return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "Connection closed")));
                }
                std::task::Poll::Ready(Ok(buf.len()))
            }
            std::task::Poll::Ready(Err(_)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "Connection closed")))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        if let Some(tx) = self.tx_frames.get_ref() {
            let _ = tx.try_send(MuxFrame {
                stream_id: self.stream_id,
                cmd: 2,
                payload: Bytes::new(),
            });
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for MuxVirtualStream {
    fn drop(&mut self) {
        if let Some(tx) = self.tx_frames.get_ref() {
            let _ = tx.try_send(MuxFrame {
                stream_id: self.stream_id,
                cmd: 2,
                payload: Bytes::new(),
            });
        }
        self.active_streams.lock().remove(&self.stream_id);
        self.conn_stream_count.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct MuxPool {
    server_addr: String,
    use_tls: bool,
    sni: Option<String>,
    min_connections: usize,
    max_connections: usize,
    max_streams_per_connection: u32,
    outbound_proxy: Option<String>,
    bind_address: Option<String>,
    connections: Arc<parking_lot::Mutex<Vec<MuxConnection>>>,
}

enum LeaseAction {
    Lease {
        stream_id: u32,
        tx_frames: mpsc::Sender<MuxFrame>,
        rx_data: mpsc::Receiver<Bytes>,
        conn_stream_count: Arc<std::sync::atomic::AtomicU32>,
        active_streams: Arc<parking_lot::Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>,
    },
    ConnectNew,
    Error,
}

impl MuxPool {
    pub fn new(
        server_addr: String,
        use_tls: bool,
        sni: Option<String>,
        min_connections: usize,
        max_connections: usize,
        max_streams_per_connection: u32,
        outbound_proxy: Option<String>,
        bind_address: Option<String>,
    ) -> Self {
        let pool = Self {
            server_addr,
            use_tls,
            sni,
            min_connections,
            max_connections,
            max_streams_per_connection,
            outbound_proxy,
            bind_address,
            connections: Arc::new(parking_lot::Mutex::new(Vec::new())),
        };

        let pool_clone = pool.clone_pool();
        tokio::spawn(async move {
            let _ = pool_clone.pre_warm().await;
        });

        pool
    }

    fn clone_pool(&self) -> Self {
        Self {
            server_addr: self.server_addr.clone(),
            use_tls: self.use_tls,
            sni: self.sni.clone(),
            min_connections: self.min_connections,
            max_connections: self.max_connections,
            max_streams_per_connection: self.max_streams_per_connection,
            outbound_proxy: self.outbound_proxy.clone(),
            bind_address: self.bind_address.clone(),
            connections: Arc::clone(&self.connections),
        }
    }

    async fn connect_one(&self) -> Result<MuxConnection, Box<dyn std::error::Error + Send + Sync>> {
        let host = if let Some(pos) = self.server_addr.find(':') {
            &self.server_addr[..pos]
        } else {
            &self.server_addr
        };
        let port = if let Some(pos) = self.server_addr.find(':') {
            self.server_addr[pos + 1..].parse::<u16>().unwrap_or(80)
        } else {
            80
        };
        let tcp = crate::transport::dial_tcp(host, port, &self.bind_address, &self.outbound_proxy).await?;
        let _ = tcp.set_nodelay(true);
        #[cfg(windows)]
        {
            use std::os::windows::io::{AsRawSocket, FromRawSocket};
            let raw = tcp.as_raw_socket();
            let socket = unsafe { socket2::Socket::from_raw_socket(raw) };
            let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
            let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
            std::mem::forget(socket);
        }
        #[cfg(not(windows))]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            let raw = tcp.as_raw_fd();
            let socket = unsafe { socket2::Socket::from_raw_fd(raw) };
            let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
            let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
            std::mem::forget(socket);
        }

        let stream = if self.use_tls {
            let sni_str = self.sni.as_deref().unwrap_or("localhost");
            let connector = crate::transport::tls::tls_helper::create_client_config(sni_str)?;
            let server_name = rustls::pki_types::ServerName::try_from(sni_str.to_string())?;
            let tls_stream = connector.connect(server_name, tcp).await?;
            OutboundTransportStream::Tls(tls_stream)
        } else {
            OutboundTransportStream::Plain(tcp)
        };

        let (r, w) = tokio::io::split(stream);
        let buf_r = tokio::io::BufReader::with_capacity(65536, r);

        let (tx_frames, rx_frames) = mpsc::channel::<MuxFrame>(256);
        let active_streams = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let active_streams_clone = Arc::clone(&active_streams);

        let writer_handle = tokio::spawn(async move {
            let _ = run_connection_writer(w, rx_frames).await;
        });

        let reader_handle = tokio::spawn(async move {
            let _ = run_connection_reader(buf_r, active_streams_clone).await;
        });

        Ok(MuxConnection {
            tx_frames,
            active_streams,
            next_stream_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            stream_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            writer_handle,
            reader_handle,
        })
    }

    pub async fn pre_warm(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let current_len = self.connections.lock().len();
            if current_len >= self.min_connections {
                break;
            }
            let conn = self.connect_one().await?;
            self.connections.lock().push(conn);
        }
        Ok(())
    }

    pub async fn lease_stream(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<MuxVirtualStream, Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let action = {
                let mut conns = self.connections.lock();
                conns.retain(|c| {
                    !c.writer_handle.is_finished() && !c.reader_handle.is_finished()
                });

                let mut selected_conn = None;
                for conn in conns.iter() {
                    let count = conn.stream_count.load(Ordering::Relaxed);
                    if count < self.max_streams_per_connection {
                        selected_conn = Some(conn);
                        break;
                    }
                }

                if let Some(conn) = selected_conn {
                    let stream_id = conn.next_stream_id.fetch_add(1, Ordering::Relaxed);
                    conn.stream_count.fetch_add(1, Ordering::Relaxed);

                    let (tx_data, rx_data) = mpsc::channel::<Bytes>(128);
                    conn.active_streams.lock().insert(stream_id, tx_data);

                    let tx_frames = conn.tx_frames.clone();
                    let conn_stream_count = Arc::clone(&conn.stream_count);
                    let active_streams = Arc::clone(&conn.active_streams);

                    LeaseAction::Lease {
                        stream_id,
                        tx_frames,
                        rx_data,
                        conn_stream_count,
                        active_streams,
                    }
                } else if conns.len() < self.max_connections {
                    LeaseAction::ConnectNew
                } else {
                    LeaseAction::Error
                }
            };

            match action {
                LeaseAction::Lease {
                    stream_id,
                    tx_frames,
                    rx_data,
                    conn_stream_count,
                    active_streams,
                } => {
                    let target_str = format!("{}:{}", target_host, target_port);
                    let open_frame = MuxFrame {
                        stream_id,
                        cmd: 1,
                        payload: Bytes::from(target_str),
                    };
                    tx_frames.send(open_frame).await?;

                    return Ok(MuxVirtualStream {
                        stream_id,
                        tx_frames: tokio_util::sync::PollSender::new(tx_frames),
                        rx_data,
                        current_read_chunk: None,
                        conn_stream_count,
                        active_streams,
                    });
                }
                LeaseAction::ConnectNew => {
                    let new_conn = self.connect_one().await?;
                    self.connections.lock().push(new_conn);
                }
                LeaseAction::Error => {
                    return Err("Connection pool capacity exceeded".into());
                }
            }
        }
    }
}
