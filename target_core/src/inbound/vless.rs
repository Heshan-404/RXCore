use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::warn;
use crate::inbound::InboundTransportStream;
use crate::state::EngineState;

// Simple VLESS implementation
// Request Format:
// 1 byte: Version (Must be 0)
// 16 bytes: User UUID
// 1 byte: Addon settings length M
// M bytes: Addons
// 1 byte: Command (1 = TCP, 2 = UDP)
// 2 bytes: Port (Big Endian)
// 1 byte: Address Type (1 = IPv4, 2 = Domain, 3 = IPv6)
// N bytes: Target address
// Response Format:
// 1 byte: Version (0)
// 1 byte: Addon settings length N
// N bytes: Addons
pub async fn parse_vless_inbound(
    stream: &mut InboundTransportStream,
    engine_state: &Arc<EngineState>,
) -> Result<(String, u16, [u8; 16]), Box<dyn std::error::Error + Send + Sync>> {
    let mut header = [0u8; 18];
    stream.read_exact(&mut header).await?;

    let version = header[0];
    if version != 0 {
        return Err("Unsupported VLESS version".into());
    }

    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&header[1..17]);

    if !engine_state.is_user_allowed(&uuid) {
        warn!("Unauthorized connection attempt with invalid user UUID");
        return Err("Invalid client UUID".into());
    }

    let addon_len = header[17] as usize;
    if addon_len > 0 {
        let mut addons = vec![0u8; addon_len];
        stream.read_exact(&mut addons).await?;
    }

    let mut cmd_port_type = [0u8; 4];
    stream.read_exact(&mut cmd_port_type).await?;

    let cmd = cmd_port_type[0];
    if cmd != 1 && cmd != 2 {
        return Err("Invalid VLESS request command".into());
    }

    let port = u16::from_be_bytes([cmd_port_type[1], cmd_port_type[2]]);
    let addr_type = cmd_port_type[3];

    let dest_addr = match addr_type {
        1 => {
            let mut ipv4 = [0u8; 4];
            stream.read_exact(&mut ipv4).await?;
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(ipv4)).to_string()
        }
        2 => {
            let mut domain_len_buf = [0u8; 1];
            stream.read_exact(&mut domain_len_buf).await?;
            let domain_len = domain_len_buf[0] as usize;
            let mut domain = vec![0u8; domain_len];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        3 => {
            let mut ipv6 = [0u8; 16];
            stream.read_exact(&mut ipv6).await?;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(ipv6)).to_string()
        }
        _ => return Err("Invalid VLESS target address type".into()),
    };

    // Send VLESS connection response header (version 0, 0 addons)
    let response = [0u8, 0u8];
    stream.write_all(&response).await?;

    Ok((dest_addr, port, uuid))
}
