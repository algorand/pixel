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
