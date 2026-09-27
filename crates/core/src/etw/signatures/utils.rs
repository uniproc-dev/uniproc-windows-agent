use std::io::Cursor;

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
