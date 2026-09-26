use binrw::BinRead;

#[derive(BinRead, Debug)]
#[br(little)]
#[allow(dead_code)]
pub struct SampledProfile {
    pub instruction_pointer: u64,
    pub thread_id: u32,
    pub count: u16,
    pub reserved: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etw::signatures::utils::parse;

    #[test]
    fn reads_the_thread_from_the_payload_not_the_header() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xDEAD_BEEF_0000_1000u64.to_le_bytes());
        buf.extend_from_slice(&4242u32.to_le_bytes());
        buf.extend_from_slice(&3u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());

        let s = parse::<SampledProfile>(&buf).expect("valid dump");
        assert_eq!(s.thread_id, 4242);
        assert_eq!(s.count, 3);
    }
}
