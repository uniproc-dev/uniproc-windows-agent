use crate::etw::signatures::utils::skip_sid;
use binrw::{BinRead, BinReaderExt, NullString, NullWideString};

// Where find: ETWExplorer for modern events, wbemtest.exe for legacy (root\wmi namespace)

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

    #[br(pad_before = 16)] // ProcessSequenceNumber(8) + CreateTime(8)
    pub parent_process_id: u32,

    #[br(pad_before = 8)] // ParentProcessSequenceNumber
    pub session_id: u32,

    #[br(pad_before = 12)] // Flags(4) + TokenElevationType(4) + TokenIsElevated(4)
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

///```c++
/// [dynamic: ToInstance, EventType{28, 31}]
/// class TcpIp_TypeGroup4 : TcpIp
/// {
///     [WmiDataId(1), read] uint32 PID;
///     [WmiDataId(2), read] uint32 size;
///     [WmiDataId(3), extension("IPAddrV6"), read] object daddr;
///     [WmiDataId(4), extension("IPAddrV6"), read] object saddr;
///     [WmiDataId(5), extension("Port"), read] object dport;
///     [WmiDataId(6), extension("Port"), read] object sport;
///     [WmiDataId(7), read] uint16 mss;
///     [WmiDataId(8), read] uint16 sackopt;
///     [WmiDataId(9), read] uint16 tsopt;
///     [WmiDataId(10), read] uint16 wsopt;
///     [WmiDataId(11), read] uint32 rcvwin;
///     [WmiDataId(12), read] sint16 rcvwinscale;
///     [WmiDataId(13), read] sint16 sndwinscale;
///     [WmiDataId(14), read] uint32 seqnum;
///     [WmiDataId(15), PointerType, read] uint32 connid;
/// };
/// ```
#[derive(BinRead, Debug)]
#[br(little)]
pub struct TcpIpTypeGroup4 {
    pub pid: u32,
    pub size: u32,
    pub dst_addr: [u8; 16],
    pub src_addr: [u8; 16],
    pub dst_port_be: u16,
    pub src_port_be: u16,
    pub mss: u16,
    pub sack_opt: u16,
    pub ts_opt: u16,
    pub ws_opt: u16,
    pub rcv_win: u32,
    pub rcv_win_scale: i16,
    pub snd_win_scale: i16,
    pub seq_num: u32,
    pub conn_id: u64,
}

/// ```c++
/// [dynamic: ToInstance, EventType(46)]
/// class SampledProfile : PerfInfo_V2
/// {
///     [WmiDataId(1), pointer, read] uint32 InstructionPointer;
///     [WmiDataId(2), read] uint32 ThreadId;
///     [WmiDataId(3), read] uint16 Count;
///     [WmiDataId(4), read] uint16 Reserved;
/// };
/// ```
#[derive(BinRead, Debug)]
#[br(little)]
pub struct SampledProfile {
    pub instruction_pointer: u64,
    pub thread_id: u32,
    pub count: u16,
    pub reserved: u16,
}

/// ```c++
/// [dynamic: ToInstance, EventType{1, 2, 3, 4}]
/// class Thread_TypeGroup1 : Thread_V4
/// {
///     [WmiDataId(1), format("x"), read] uint32 ProcessId;
///     [WmiDataId(2), format("x"), read] uint32 TThreadId;
///     [WmiDataId(3), pointer, read] uint32 StackBase;
///     [WmiDataId(4), pointer, read] uint32 StackLimit;
///     [WmiDataId(5), pointer, read] uint32 UserStackBase;
///     [WmiDataId(6), pointer, read] uint32 UserStackLimit;
///     [WmiDataId(7), pointer, read] uint32 Affinity;
///     [WmiDataId(8), pointer, read] uint32 Win32StartAddr;
///     [WmiDataId(9), pointer, read] uint32 TebBase;
///     [WmiDataId(10), format("x"), read] uint32 SubProcessTag;
///     [WmiDataId(11), read] uint8 BasePriority;
///     [WmiDataId(12), read] uint8 PagePriority;
///     [WmiDataId(13), read] uint8 IoPriority;
///     [WmiDataId(14), read] uint8 ThreadFlags;
///     [WmiDataId(15), StringTermination("NullTerminated"), format("w"), read] string ThreadName;
/// };
/// ```
#[derive(BinRead, Debug)]
#[br(little)]
pub struct ThreadTypeGroup1 {
    pub process_id: u32,
    pub thread_id: u32,
    // pub stack_base: u64,
    // pub stack_limit: u64,
    // pub user_stack_base: u64,
    // pub user_stack_limit: u64,
    // pub affinity: u64,
    // pub win32_start_addr: u64,
    // pub teb_base: u64,
    // pub sub_process_tag: u32,
    // pub base_priority: u8,
    // pub page_priority: u8,
    // pub io_priority: u8,
    // pub thread_flags: u8,
    // pub thread_name: NullWideString,
}

#[derive(BinRead, Debug)]
#[br(little)]
pub struct ProcessStopData {
    pub process_id: u32,
    pub parent_process_id: u32,
    pub session_id: u32,
}
