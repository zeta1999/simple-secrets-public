use crate::crypto::pqc_auth::Encryptor;
use secure_memory::error::Error;
use secure_memory::kem::encapsulate;
use secure_memory::LockedBuffer;

pub struct PairingSession {
    encryptor: Encryptor,
}

impl PairingSession {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            encryptor: Encryptor::generate()?,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        self.encryptor.public_key()
    }

    pub fn receive_encapsulated_secret(&self, ciphertext: &[u8]) -> Result<LockedBuffer, Error> {
        self.encryptor.decapsulate(ciphertext)
    }
}

pub fn generate_encapsulated_secret(
    peer_public_key: &[u8],
) -> Result<(Vec<u8>, LockedBuffer), Error> {
    encapsulate(peer_public_key)
}
