use binrw::{BinRead, NullWideString};

use crate::etw::signatures::utils::skip_sid;

/// ```xml
/// <template tid="ProcessStartArgs_V4">
///   <data name="ProcessID" inType="win:UInt32" />
///   <data name="ProcessSequenceNumber" inType="win:UInt64" />
///   <data name="CreateTime" inType="win:FILETIME" />
///   <data name="ParentProcessID" inType="win:UInt32" />
///   <data name="ParentProcessSequenceNumber" inType="win:UInt64" />
///   <data name="SessionID" inType="win:UInt32" />
///   <data name="Flags" inType="win:UInt32" />
///   <data name="ProcessTokenElevationType" inType="win:UInt32" />
///   <data name="ProcessTokenIsElevated" inType="win:UInt32" />
///   <data name="MandatoryLabel" inType="win:SID" />
///   <data name="ImageName" inType="win:UnicodeString" />
///   <data name="ImageChecksum" inType="win:UInt32" />
///   <data name="TimeDateStamp" inType="win:UInt32" />
///   <data name="PackageFullName" inType="win:UnicodeString" />
///   <data name="PackageRelativeAppId" inType="win:UnicodeString" />
///   <data name="SecurityMitigations" inType="win:UInt32" />
/// </template>
/// ```
#[derive(BinRead)]
#[br(little)]
#[allow(dead_code)]
pub struct ProcessStartV4Header {
    pub process_id: u32,

    #[br(pad_before = 16)] // ProcessSequenceNumber(8) + CreateTime(8)
    pub parent_process_id: u32,

    #[br(pad_before = 8)] // ParentProcessSequenceNumber
    pub session_id: u32,

    #[br(pad_before = 12)] // Flags(4) + TokenElevationType(4) + TokenIsElevated(4)
    #[br(parse_with = skip_sid)]
    _sid: (),

    pub image_name: NullWideString,
    pub image_checksum: u32,
    pub time_date_stamp: u32,

    pub package_full_name: NullWideString,
    pub package_relative_app_id: NullWideString,
}

/// ```c++
/// [dynamic: ToInstance, EventType{1, 2, 3, 4}]
/// class Thread_TypeGroup1 : Thread_V4
/// {
///     [WmiDataId(1), format("x"), read] uint32 ProcessId;
///     [WmiDataId(2), format("x"), read] uint32 TThreadId;
///     ...
/// };
/// ```
#[derive(BinRead, Debug)]
#[br(little)]
pub struct ThreadTypeGroup1 {
    pub process_id: u32,
    pub thread_id: u32,
}

#[derive(BinRead, Debug)]
#[br(little)]
#[allow(dead_code)]
pub struct ProcessStopData {
    pub process_id: u32,
    pub parent_process_id: u32,
    pub session_id: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etw::signatures::utils::parse;

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|c| c.to_le_bytes())
            .collect()
    }

    fn start_dump() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&4242u32.to_le_bytes()); // process_id
        v.extend_from_slice(&[0u8; 16]); // ProcessSequenceNumber + CreateTime
        v.extend_from_slice(&1000u32.to_le_bytes()); // parent_process_id
        v.extend_from_slice(&[0u8; 8]); // ParentProcessSequenceNumber
        v.extend_from_slice(&1u32.to_le_bytes()); // session_id
        v.extend_from_slice(&[0u8; 12]); // Flags + TokenElevationType + TokenIsElevated
        // SID: revision=1, sub_count=2, authority(6), sub_authorities(2 * u32)
        v.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 5]);
        v.extend_from_slice(&[0u8; 8]);
        v.extend_from_slice(&utf16z("cmd.exe")); // image_name
        v.extend_from_slice(&0xDEADu32.to_le_bytes()); // image_checksum
        v.extend_from_slice(&0xBEEFu32.to_le_bytes()); // time_date_stamp
        v.extend_from_slice(&utf16z("Pkg!App")); // package_full_name
        v.extend_from_slice(&utf16z("App")); // package_relative_app_id
        v
    }

    #[test]
    fn parses_process_start_v4() {
        let h = parse::<ProcessStartV4Header>(&start_dump()).expect("valid dump");
        assert_eq!(h.process_id, 4242);
        assert_eq!(h.parent_process_id, 1000);
        assert_eq!(h.session_id, 1);
        assert_eq!(h.image_name.to_string(), "cmd.exe");
        assert_eq!(h.image_checksum, 0xDEAD);
        assert_eq!(h.package_full_name.to_string(), "Pkg!App");
        assert_eq!(h.package_relative_app_id.to_string(), "App");
    }

    #[test]
    fn parses_process_stop() {
        let mut v = Vec::new();
        v.extend_from_slice(&4242u32.to_le_bytes());
        v.extend_from_slice(&1000u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        let s = parse::<ProcessStopData>(&v).expect("valid dump");
        assert_eq!(s.process_id, 4242);
        assert_eq!(s.parent_process_id, 1000);
    }

    #[test]
    fn parses_thread_type_group1() {
        let mut v = Vec::new();
        v.extend_from_slice(&4242u32.to_le_bytes());
        v.extend_from_slice(&777u32.to_le_bytes());
        let t = parse::<ThreadTypeGroup1>(&v).expect("valid dump");
        assert_eq!(t.process_id, 4242);
        assert_eq!(t.thread_id, 777);
    }

    #[test]
    fn truncated_dump_is_none() {
        assert!(parse::<ProcessStartV4Header>(&start_dump()[..8]).is_none());
    }
}
