use secure_memory::error::Error;
use secure_memory::kem::{encapsulate, KemKeyPair};
use secure_memory::sig::SigKeyPair;
use secure_memory::LockedBuffer;

/// PQC Authentication using ML-DSA-65 signatures.
pub struct Authenticator {
    keypair: SigKeyPair,
}

impl Authenticator {
    /// Generates a new PQC authentication key pair.
    pub fn generate() -> Result<Self, Error> {
        let keypair = SigKeyPair::generate()?;
        Ok(Self { keypair })
    }

    /// Signs a message deterministically.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.keypair.sign(message)
    }

    /// Verifies a signature against a message and a verifying key.
    pub fn verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, Error> {
        SigKeyPair::verify(verifying_key, message, signature)
    }

    pub fn public_key(&self) -> &[u8] {
        self.keypair.verifying_key()
    }
}

/// PQC Encryption (KEM) using ML-KEM-768
pub struct Encryptor {
    keypair: KemKeyPair,
}

impl Encryptor {
    /// Generates a new PQC KEM key pair.
    pub fn generate() -> Result<Self, Error> {
        let keypair = KemKeyPair::generate()?;
        Ok(Self { keypair })
    }

    /// Decapsulates a ciphertext to retrieve the shared secret.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<LockedBuffer, Error> {
        self.keypair.decapsulate(ciphertext)
    }

    pub fn public_key(&self) -> &[u8] {
        self.keypair.public_key()
    }
}

/// Encapsulates a shared secret for a given public key.
pub fn kem_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, LockedBuffer), Error> {
    encapsulate(public_key)
}
