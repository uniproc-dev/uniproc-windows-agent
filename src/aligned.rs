/// A zeroed byte buffer whose start is aligned for any Win32 structure written into it.
pub struct AlignedBuf {
    words: Vec<u64>,
    len: usize,
}

impl AlignedBuf {
    pub fn zeroed(len: usize) -> Self {
        Self {
            words: vec![0; len.div_ceil(size_of::<u64>())],
            len,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr().cast()
    }
}

#[cfg(test)]
mod tests {
    use super::AlignedBuf;

    fn is_aligned(buf: &AlignedBuf) -> bool {
        (buf.as_ptr() as usize).is_multiple_of(align_of::<u64>())
    }

    #[test]
    fn every_length_starts_on_an_eight_byte_boundary() {
        for len in [0, 1, 7, 8, 9, 1023, 4096, 1 << 20] {
            let buf = AlignedBuf::zeroed(len);
            assert!(is_aligned(&buf), "misaligned at len {len}");
            assert_eq!(buf.len(), len);
        }
    }

    #[test]
    fn the_whole_length_is_writable_and_starts_zeroed() {
        let mut buf = AlignedBuf::zeroed(21);
        let bytes = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr(), buf.len()) };
        assert!(bytes.iter().all(|b| *b == 0));
        bytes.fill(0xAB);
        assert_eq!(bytes[20], 0xAB);
    }
}
