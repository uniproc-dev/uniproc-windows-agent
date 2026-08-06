use binrw::BinRead;

/// ```c++
/// [dynamic: ToInstance, EventType{10, 11}, EventTypeName{"Read", "Write"}]
/// class DiskIo_TypeGroup1 : DiskIo
/// {
///     [WmiDataId(1), read] uint32 DiskNumber;
///     [WmiDataId(2), format("x"), read] uint32 IrpFlags;
///     [WmiDataId(3), read] uint32 TransferSize;
///     [WmiDataId(4), read] uint32 Reserved;
///     [WmiDataId(5), read] sint64 ByteOffset;
///     [WmiDataId(6), pointer, read] uint32 FileObject;
///     [WmiDataId(7), pointer, read] uint32 Irp;
///     [WmiDataId(8), read] uint64 HighResResponseTime;
///     [WmiDataId(9), read] uint32 IssuingThreadId;
/// };
/// ```
#[derive(BinRead, Debug)]
#[br(little)]
#[allow(dead_code)]
pub struct DiskIoTypeGroup1 {
    pub disk_number: u32,
    pub irp_flags: u32,
    pub transfer_size: u32,
    pub reserved: u32,
    pub byte_offset: i64,
    pub file_object: u64,
    pub irp: u64,
    pub high_res_response_time: u64,
    pub issuing_thread_id: u32,
}

/// ```c++
/// [dynamic: ToInstance, EventType{14}, EventTypeName{"FlushBuffers"}]
/// class DiskIo_TypeGroup3 : DiskIo
/// {
///     [WmiDataId(1), read] uint32 DiskNumber;
///     [WmiDataId(2), format("x"), read] uint32 IrpFlags;
///     [WmiDataId(3), read] uint64 HighResResponseTime;
///     [WmiDataId(4), pointer, read] uint32 Irp;
///     [WmiDataId(5), read] uint32 IssuingThreadId;
/// };
/// ```
#[derive(BinRead, Debug)]
#[br(little)]
#[allow(dead_code)]
pub struct DiskIoTypeGroup3 {
    pub disk_number: u32,
    pub irp_flags: u32,
    pub high_res_response_time: u64,
    pub irp: u64,
    pub issuing_thread_id: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etw::signatures::utils::parse;

    fn group1_dump() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&2u32.to_le_bytes()); // disk_number
        v.extend_from_slice(&0x43u32.to_le_bytes()); // irp_flags
        v.extend_from_slice(&4096u32.to_le_bytes()); // transfer_size
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        v.extend_from_slice(&0x1234_5678i64.to_le_bytes()); // byte_offset
        v.extend_from_slice(&0xAAAA_0001u64.to_le_bytes()); // file_object
        v.extend_from_slice(&0xBBBB_0002u64.to_le_bytes()); // irp
        v.extend_from_slice(&777u64.to_le_bytes()); // high_res_response_time
        v.extend_from_slice(&99u32.to_le_bytes()); // issuing_thread_id
        v
    }

    fn group3_dump() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&2u32.to_le_bytes()); // disk_number
        v.extend_from_slice(&0u32.to_le_bytes()); // irp_flags
        v.extend_from_slice(&777u64.to_le_bytes()); // high_res_response_time
        v.extend_from_slice(&0xBBBB_0002u64.to_le_bytes()); // irp
        v.extend_from_slice(&99u32.to_le_bytes()); // issuing_thread_id
        v
    }

    #[test]
    fn parses_disk_io_type_group1() {
        let g = parse::<DiskIoTypeGroup1>(&group1_dump()).expect("valid dump");
        assert_eq!(g.disk_number, 2);
        assert_eq!(g.transfer_size, 4096);
        assert_eq!(g.byte_offset, 0x1234_5678);
        assert_eq!(g.irp, 0xBBBB_0002);
        assert_eq!(g.issuing_thread_id, 99);
    }

    #[test]
    fn parses_disk_io_type_group3() {
        let g = parse::<DiskIoTypeGroup3>(&group3_dump()).expect("valid dump");
        assert_eq!(g.disk_number, 2);
        assert_eq!(g.high_res_response_time, 777);
        assert_eq!(g.irp, 0xBBBB_0002);
    }

    #[test]
    fn truncated_dump_is_none() {
        assert!(parse::<DiskIoTypeGroup1>(&group1_dump()[..7]).is_none());
        assert!(parse::<DiskIoTypeGroup3>(&group3_dump()[..7]).is_none());
    }
}
