use crate::etw::signatures::utils::skip_sid;
use binrw::{BinRead, BinReaderExt, NullString, NullWideString};

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
pub struct ProcessStartV4Header {
    pub process_id: u32,

    #[br(pad_before = 16)]  // ProcessSequenceNumber(8) + CreateTime(8)
    pub parent_process_id: u32,

    #[br(pad_before = 8)]   // ParentProcessSequenceNumber
    pub session_id: u32,

    #[br(pad_before = 12)]  // Flags(4) + TokenElevationType(4) + TokenIsElevated(4)
    #[br(parse_with = skip_sid)]
    _sid: (),

    pub image_name: NullWideString,
}


/// ```c++
/// [dynamic: ToInstance, EventType{1, 2, 3, 4, 39}]
/// class Process_V4_TypeGroup1 : Process_V4
/// {
/// 	[WmiDataId(7), read] uint32 Flags = NULL;
/// 	[WmiDataId(1), pointer, read] uint32 UniqueProcessKey;
/// 	[WmiDataId(2), format("x"), read] uint32 ProcessId;
/// 	[WmiDataId(3), format("x"), read] uint32 ParentId;
/// 	[WmiDataId(4), read] uint32 SessionId;
/// 	[WmiDataId(5), read] sint32 ExitStatus;
/// 	[WmiDataId(6), pointer, read] uint32 DirectoryTableBase;
/// 	[WmiDataId(8), extension("Sid"), read] object UserSID;
/// 	[WmiDataId(9), StringTermination("NullTerminated"), read] string ImageFileName;
/// 	[WmiDataId(10), StringTermination("NullTerminated"), format("w"), read] string CommandLine;
/// 	[WmiDataId(11), StringTermination("NullTerminated"), format("w"), read] string PackageFullName;
/// 	[WmiDataId(12), StringTermination("NullTerminated"), format("w"), read] string ApplicationId;
/// };
/// ```
#[derive(BinRead, Debug)]
#[br(little)]
pub struct ProcessV4TypeGroup1 {
    pub unique_process_key: u64,
    pub process_id: u32,
    pub parent_id: u32,
    pub session_id: u32,
    pub exit_status: i32,
    pub directory_table_base: u64,
    pub flags: u32,
    pub pointer1: u64,
    pub unknown: u64,
    #[br(parse_with = skip_sid)]
    _sid: (),
    pub image_file_name: NullString,
    pub command_line: NullWideString,
    pub package_full_name: NullWideString,
    pub application_id: NullWideString,
}
