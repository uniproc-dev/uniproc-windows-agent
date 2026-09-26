/// A value and the tag it was taken under: an unchanged tag means an unchanged value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tagged<T> {
    pub etag: u64,
    pub value: T,
}

/// One run's half of every tag it hands out, so a restarted agent never
/// repeats a tag a client still holds. Never zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Epoch(u32);

impl Epoch {
    pub fn new() -> Self {
        loop {
            match getrandom::u32() {
                Ok(0) => continue,
                Ok(epoch) => return Self(epoch),
                Err(_) => {
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.subsec_nanos());
                    return Self(nanos | 1);
                }
            }
        }
    }

    /// The tag of the `generation`th version of a value; never zero.
    pub fn tag(self, generation: u32) -> u64 {
        (self.0 as u64) << 32 | generation as u64
    }
}

impl Default for Epoch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_is_never_zero() {
        assert_ne!(Epoch::new().tag(0), 0);
    }

    #[test]
    fn two_runs_start_from_different_tags() {
        assert_ne!(Epoch::new().tag(0), Epoch::new().tag(0));
    }
}
