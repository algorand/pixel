use PixelG1;

/// The public key structure is a wrapper of `PixelG2` group.
/// The actual group that the public key lies in depends on `pk_in_g2` flag.
#[derive(Debug, Clone, Default)]
pub struct ProofOfPossession {
    /// ciphersuite id
    ciphersuite: u8,
    /// the actual public key element
    pop: PixelG1,
}

impl ProofOfPossession {
    /// Cosntruct a PoP object.
    pub fn construct(ciphersuite: u8, pop: PixelG1) -> Self {
        Self { ciphersuite, pop }
    }

    /// Access the ciphersuite id
    pub fn get_ciphersuite(&self) -> u8 {
        self.ciphersuite
    }

    /// Access the signature element of pop.
    pub fn get_pop(&self) -> PixelG1 {
        self.pop
    }

    // the actual pop generation and verification functions
    // stay within the public key module
}
