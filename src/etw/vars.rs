macro_rules! guid {
    ($s:literal) => {{
        const BYTES: &[u8] = $s.as_bytes();
        const fn hex(b: u8) -> u8 {
            match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid hex char"),
            }
        }
        const fn byte(hi: u8, lo: u8) -> u8 {
            hex(hi) << 4 | hex(lo)
        }
        ::windows::core::GUID::from_values(
            u32::from_be_bytes([
                byte(BYTES[0], BYTES[1]),
                byte(BYTES[2], BYTES[3]),
                byte(BYTES[4], BYTES[5]),
                byte(BYTES[6], BYTES[7]),
            ]),
            u16::from_be_bytes([byte(BYTES[9], BYTES[10]), byte(BYTES[11], BYTES[12])]),
            u16::from_be_bytes([byte(BYTES[14], BYTES[15]), byte(BYTES[16], BYTES[17])]),
            [
                byte(BYTES[19], BYTES[20]),
                byte(BYTES[21], BYTES[22]),
                byte(BYTES[24], BYTES[25]),
                byte(BYTES[26], BYTES[27]),
                byte(BYTES[28], BYTES[29]),
                byte(BYTES[30], BYTES[31]),
                byte(BYTES[32], BYTES[33]),
                byte(BYTES[34], BYTES[35]),
            ],
        )
    }};
}

pub(crate) use guid;

pub const KERNEL_SESSION_NAME: &str = "Uniproc-Kernel";
pub const SESSION_NAME_PREFIX: &str = "Uniproc-";

// EVENT_TRACE_PROPERTIES tuning.
pub const BUFFER_SIZE_KB: u32 = 64;
pub const MINIMUM_BUFFERS: u32 = 1;
pub const MAXIMUM_BUFFERS: u32 = 8;
pub const FLUSH_TIMER_SEC: u32 = 1;
