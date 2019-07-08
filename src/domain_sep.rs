//! This module lists the domain seperators in Pixel.

// prefix of hash_to_field used in hash(msg) -> Fr
pub const DOM_SEP_HASH_TO_MSG: &str = "Pixel hash to message";

// prefix of hash_to_field to generate the randomness for signing
pub const DOM_SEP_SIG: &str = "Pixel randomness for signing";

// prefix of hash_to_field to generate the randomness for key updating
pub const DOM_SEP_KEY_UPDATE: &str = "Pixel randomness for key updating";

// prefix of hash_to_field to generate the master key alpha
pub const DOM_SEP_MASTER_KEY: &str = "Pixel master key";

// prefix of hash_to_field to generate the root key: sk at time 1
pub const DOM_SEP_KEY_INIT: &str = "Pixel randomness for root key";

// prefix of hash_to_group to generate public parameters
pub const DOM_SEP_PARAM_GEN: &str = "Pixel public parameter generation";

// prefix of sha256 to initiate a seed
pub const DOM_SEP_SEED_INIT: &str = "Pixel prng seed initiate";

// prefix of sha256 to update the seed
pub const DOM_SEP_SEED_UPDATE: &str = "Pixel prng seed update";

// prefix of sha256 to generate a new seed
pub const DOM_SEP_SEED_EXTRACT: &str = "Pixel prng seed extraction";
