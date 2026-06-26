/// Pluggable Entropy/RNG source trait
pub trait EntropySource {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), String>;
}

/// A default implementation using standard OS RNG
pub struct DefaultEntropySource;

impl EntropySource for DefaultEntropySource {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), String> {
        // Implementation will go here using `rand` crate
        // For example: rand::RngCore::fill_bytes(&mut rand::thread_rng(), dest);
        use rand::RngCore;
        rand::thread_rng().fill_bytes(dest);
        Ok(())
    }
}
