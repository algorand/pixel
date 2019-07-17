use ProofOfPossession;
use bls_sigs_ref_rs::BLSSignature;
use domain_sep;
use param::{PubParam, VALID_CIPHERSUITE};
use pixel_err::*;
use serdes::SerDes;
use PixelG2;
use PK_LEN;

/// The public key structure is a wrapper of `PixelG2` group.
/// The actual group that the public key lies in depends on `pk_in_g2` flag.
#[derive(Debug, Clone, Default)]
pub struct PublicKey {
    /// ciphersuite id
    ciphersuite: u8,
    /// the actual public key element
    pk: PixelG2,
}

impl PublicKey {
    /// Initialize the PublicKey with a given pk.
    /// Returns an error if the ciphersuite id (in parameter) is not valid
    pub fn init(pp: &PubParam, pk: PixelG2) -> Result<Self, String> {
        // check that the ciphersuite identifier is correct
        if !VALID_CIPHERSUITE.contains(&pp.get_ciphersuite()) {
            #[cfg(debug_assertions)]
            println!("Incorrect ciphersuite id: {}", pp.get_ciphersuite());
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        Ok(PublicKey {
            ciphersuite: pp.get_ciphersuite(),
            pk,
        })
    }

    /// Constructing a PublicKey object.
    pub fn construct(ciphersuite: u8, pk: PixelG2) -> Self {
        PublicKey { ciphersuite, pk }
    }

    /// This function returns the storage requirement for this Public Key
    pub fn get_size(&self) -> usize {
        PK_LEN
    }

    /// Returns the public key element this structure contains.
    pub fn get_pk(&self) -> PixelG2 {
        self.pk
    }

    /// Returns the public key element this structure contains.
    pub fn get_ciphersuite(&self) -> u8 {
        self.ciphersuite
    }

    /// This function validates the public key against the
    /// proof_of_possession using BLS verification algorithm.
    pub fn validate(&self, pop: &ProofOfPossession) -> bool {
        // check that the ciphersuite identifier is correct
        if !VALID_CIPHERSUITE.contains(&self.get_ciphersuite()) {
            #[cfg(debug_assertions)]
            println!("Incorrect ciphersuite id: {}", self.get_ciphersuite());
            return false;
        }
        if self.get_ciphersuite() != pop.get_ciphersuite() {
            #[cfg(debug_assertions)]
            println!("Incorrect ciphersuite id: {}", self.get_ciphersuite());
            return false;
        }

        // buf = DOM_SEP_POP | serial (PK)
        let mut buf = domain_sep::DOM_SEP_POP.as_bytes().to_vec();
        if self.get_pk().serialize(&mut buf, true).is_err() {
            #[cfg(debug_assertions)]
            println!("Serialization failure on public key");
            return false;
        };
        // return the output of verification
        BLSSignature::verify(self.get_pk(), pop.get_pop(), buf, self.get_ciphersuite())
    }
}

impl std::cmp::PartialEq for PublicKey {
    /// Convenient function to compare secret key objects
    fn eq(&self, other: &Self) -> bool {
        self.ciphersuite == other.ciphersuite && self.pk == other.pk
    }
}
