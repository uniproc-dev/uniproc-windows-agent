use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;

pub fn to_user_data(record: &EVENT_RECORD) -> Option<&[u8]> {
    if record.UserData.is_null() || record.UserDataLength == 0 {
        return None;
    }
    Some(unsafe {
        std::slice::from_raw_parts(record.UserData as *const u8, record.UserDataLength as usize)
    })
}
