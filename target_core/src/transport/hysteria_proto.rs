use bytes::{Buf, BufMut, Bytes, BytesMut};

pub fn read_varint<B: Buf>(buf: &mut B) -> Option<u64> {
    if !buf.has_remaining() {
        return None;
    }
    let first = buf.chunk()[0];
    let msbits = first >> 6;
    let len = 1 << msbits;
    if buf.remaining() < len {
        return None;
    }
    let mut val = (first & 0x3F) as u64;
    buf.advance(1);
    for _ in 1..len {
        val = (val << 8) | (buf.get_u8() as u64);
    }
    Some(val)
}

pub fn write_varint<B: BufMut>(buf: &mut B, val: u64) {
    if val < 64 {
        buf.put_u8(val as u8);
    } else if val < 16384 {
        buf.put_u8(((val >> 8) as u8) | 0x40);
        buf.put_u8((val & 0xFF) as u8);
    } else if val < 1073741824 {
        buf.put_u8(((val >> 24) as u8) | 0x80);
        buf.put_u8(((val >> 16) & 0xFF) as u8);
        buf.put_u8(((val >> 8) & 0xFF) as u8);
        buf.put_u8((val & 0xFF) as u8);
    } else {
        buf.put_u8(((val >> 56) as u8) | 0xC0);
        buf.put_u8(((val >> 48) & 0xFF) as u8);
        buf.put_u8(((val >> 40) & 0xFF) as u8);
        buf.put_u8(((val >> 32) & 0xFF) as u8);
        buf.put_u8(((val >> 24) & 0xFF) as u8);
        buf.put_u8(((val >> 16) & 0xFF) as u8);
        buf.put_u8(((val >> 8) & 0xFF) as u8);
        buf.put_u8((val & 0xFF) as u8);
    }
}

#[derive(Debug, Clone)]
pub struct TCPRequest {
    pub address: String,
}

impl TCPRequest {
    pub fn parse<B: Buf>(buf: &mut B) -> Option<Self> {
        let req_id = read_varint(buf)?;
        if req_id != 0x401 {
            return None;
        }
        let addr_len = read_varint(buf)? as usize;
        if buf.remaining() < addr_len {
            return None;
        }
        let mut addr_bytes = vec![0u8; addr_len];
        buf.copy_to_slice(&mut addr_bytes);
        let address = String::from_utf8(addr_bytes).ok()?;

        let padding_len = read_varint(buf)? as usize;
        if buf.remaining() < padding_len {
            return None;
        }
        buf.advance(padding_len);

        Some(Self { address })
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0x401);
        write_varint(&mut buf, self.address.len() as u64);
        buf.put_slice(self.address.as_bytes());
        write_varint(&mut buf, 0); // Padding length = 0
        buf.freeze()
    }
}

#[derive(Debug, Clone)]
pub struct TCPResponse {
    pub status: u8,
    pub error_message: Option<String>,
}

impl TCPResponse {
    pub fn parse<B: Buf>(buf: &mut B) -> Option<Self> {
        if !buf.has_remaining() {
            return None;
        }
        let status = buf.get_u8();
        let mut error_message = None;
        if status != 0 {
            let msg_len = read_varint(buf)? as usize;
            if buf.remaining() < msg_len {
                return None;
            }
            let mut msg_bytes = vec![0u8; msg_len];
            buf.copy_to_slice(&mut msg_bytes);
            error_message = String::from_utf8(msg_bytes).ok();
        }
        Some(Self { status, error_message })
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(self.status);
        if self.status != 0 {
            if let Some(ref msg) = self.error_message {
                write_varint(&mut buf, msg.len() as u64);
                buf.put_slice(msg.as_bytes());
            } else {
                write_varint(&mut buf, 0);
            }
        }
        buf.freeze()
    }
}

#[derive(Debug, Clone)]
pub struct UDPMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub address: String,
    pub payload: Bytes,
}

impl UDPMessage {
    pub fn parse(mut buf: Bytes) -> Option<Self> {
        if buf.remaining() < 8 {
            return None;
        }
        let session_id = buf.get_u32();
        let packet_id = buf.get_u16();
        let fragment_id = buf.get_u8();
        let fragment_count = buf.get_u8();

        let addr_len = read_varint(&mut buf)? as usize;
        if buf.remaining() < addr_len {
            return None;
        }
        let mut addr_bytes = vec![0u8; addr_len];
        buf.copy_to_slice(&mut addr_bytes);
        let address = String::from_utf8(addr_bytes).ok()?;

        let payload = buf;

        Some(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address,
            payload,
        })
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u32(self.session_id);
        buf.put_u16(self.packet_id);
        buf.put_u8(self.fragment_id);
        buf.put_u8(self.fragment_count);
        write_varint(&mut buf, self.address.len() as u64);
        buf.put_slice(self.address.as_bytes());
        buf.put_slice(&self.payload);
        buf.freeze()
    }
}
