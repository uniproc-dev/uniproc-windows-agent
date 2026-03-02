use std::io::{Read, Seek};
use log::{info, warn};
use windows::Win32::Security::{SID, SID_IDENTIFIER_AUTHORITY};

pub fn skip_sid<R: Read + Seek>(
    reader: &mut R,
    _: binrw::Endian,
    _: (),
) -> binrw::BinResult<()> {

    let mut header = [0u8; 8];  // Revision(1) + SubCount(1) + Authority(6)
    reader.read_exact(&mut header)?;

    let count = header[1] as usize;  // SubAuthorityCount
    info!("Revision {}, SubAuthorityCount: {}, skip bytes: {}", header[0], header[1], count * 4);

    let mut sub_authorities = vec![0u8; count * 4];

    reader.read_exact(&mut sub_authorities)?;

    Ok(())
}
