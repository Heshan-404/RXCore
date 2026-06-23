use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::warn;
use crate::inbound::InboundTransportStream;
use crate::state::EngineState;

async fn read_exact_to_buf<R: tokio::io::AsyncReadExt + Unpin>(
    stream: &mut R,
    buf: &mut bytes::BytesMut,
    needed: usize,
) -> std::io::Result<()> {
    let current_len = buf.len();
    if current_len < needed {
        buf.resize(needed, 0);
        stream.read_exact(&mut buf[current_len..needed]).await?;
    }
    Ok(())
}

pub async fn parse_vless_inbound(
    stream: &mut InboundTransportStream,
    engine_state: &Arc<EngineState>,
) -> Result<(String, u16, [u8; 16], u8), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = bytes::BytesMut::with_capacity(256);

    read_exact_to_buf(stream, &mut buf, 18).await?;

    let version = buf[0];
    if version != 0 {
        return Err("Unsupported VLESS version".into());
    }

    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&buf[1..17]);

    if !engine_state.is_user_allowed(&uuid) {
        warn!("Unauthorized connection attempt with invalid user UUID");
        return Err("Invalid client UUID".into());
    }

    let addon_len = buf[17] as usize;
    let header_offset = 18;

    let min_needed = header_offset + addon_len + 4;
    read_exact_to_buf(stream, &mut buf, min_needed).await?;

    let cmd_port_type_start = header_offset + addon_len;
    let cmd = buf[cmd_port_type_start];
    if cmd != 1 && cmd != 2 {
        return Err("Invalid VLESS request command".into());
    }

    let port = u16::from_be_bytes([buf[cmd_port_type_start + 1], buf[cmd_port_type_start + 2]]);
    let addr_type = buf[cmd_port_type_start + 3];

    let dest_addr_start = cmd_port_type_start + 4;
    let dest_addr = match addr_type {
        1 => {
            let needed = dest_addr_start + 4;
            read_exact_to_buf(stream, &mut buf, needed).await?;
            let octets: [u8; 4] = buf[dest_addr_start..needed].try_into()?;
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)).to_string()
        }
        2 => {
            let needed = dest_addr_start + 1;
            read_exact_to_buf(stream, &mut buf, needed).await?;
            let domain_len = buf[dest_addr_start] as usize;
            let needed = dest_addr_start + 1 + domain_len;
            read_exact_to_buf(stream, &mut buf, needed).await?;
            let domain_slice = &buf[dest_addr_start + 1..needed];
            std::str::from_utf8(domain_slice)?.to_string()
        }
        3 => {
            let needed = dest_addr_start + 16;
            read_exact_to_buf(stream, &mut buf, needed).await?;
            let octets: [u8; 16] = buf[dest_addr_start..needed].try_into()?;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)).to_string()
        }
        _ => return Err("Invalid VLESS target address type".into()),
    };

    let response = [0u8, 0u8];
    stream.write_all(&response).await?;

    Ok((dest_addr, port, uuid, cmd))
}
