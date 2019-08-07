use PixelG1;

/// The public key structure is a wrapper of `PixelG2` group.
/// The actual group that the public key lies in depends on `pk_in_g2` flag.
#[derive(Debug, Clone, Default)]
pub struct ProofOfPossession {
    /// ciphersuite id
    ciphersuite: u8,
    /// the actual pop element
    pop: PixelG1,
}

impl ProofOfPossession {
    /// Cosntruct a PoP object.
    pub fn new(ciphersuite: u8, pop: PixelG1) -> Self {
        Self { ciphersuite, pop }
    }

    /// Access the ciphersuite id
    pub fn ciphersuite(&self) -> u8 {
        self.ciphersuite
    }

    /// Access the signature element of pop.
    pub fn pop(&self) -> PixelG1 {
        self.pop
    }

    // the actual pop generation is within the master_key_gen function
    // since the secret exponent is not available anywhere else
    // the verification function is within the public key module
}
