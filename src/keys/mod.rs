use pairing::bls12_381::G1;
use pairing::bls12_381::G2;
use param::CONST_D;

pub mod keypair; //  public secret key pairs
pub mod secretkey; // secret key
pub mod subsecretkey; //  subsecret keys

// the secret key is a list of SubSecretKeys
// the length is arbitrary
#[derive(Debug, Clone)]
pub struct SecretKey {
    time: u64, // smallest timestamp for all subkeys
    ssk: Vec<SubSecretKey>,
}

#[derive(Debug, Clone, Copy)]
pub struct SubSecretKey {
    time: u64,  //  timestamp for the current key
    g2r: G2,    //  g2^r
    g1poly: G1, //  g1^{alpha + f(x) r}
    // the first d-1 elements are for delegations
    // the last element is for the message
    d_elements: [G1; CONST_D],
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    sk: SecretKey,
    pk: G2,
}
