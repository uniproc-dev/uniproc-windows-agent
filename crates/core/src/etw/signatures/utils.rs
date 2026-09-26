use std::io::{Cursor, Read, Seek};

use binrw::BinRead;
use tracing::warn;

pub fn parse<T: for<'a> BinRead<Args<'a> = ()>>(data: &[u8]) -> Option<T> {
    match T::read_options(&mut Cursor::new(data), binrw::Endian::Little, ()) {
        Ok(v) => Some(v),
        Err(e) => {
            warn!("etw parse {} failed: {e}", std::any::type_name::<T>());
            None
        }
    }
}

pub fn skip_sid<R: Read + Seek>(reader: &mut R, _: binrw::Endian, _: ()) -> binrw::BinResult<()> {
    let mut header = [0u8; 8]; // Revision(1) + SubCount(1) + Authority(6)
    reader.read_exact(&mut header)?;

    let count = header[1] as usize; // SubAuthorityCount

    let mut sub_authorities = vec![0u8; count * 4];

    reader.read_exact(&mut sub_authorities)?;

    Ok(())
}
