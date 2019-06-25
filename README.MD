# Pixel signature scheme

## Build options

* `cargo build` builds a debug version; with time depth parameter = 4;
* `cargo build --release` builds the release version; with time depth parameter = 30
* `cargo build --features=pk_in_g2` builds a version where the public key lies in `G2` or `bls12-381` curve; it is turned off by default.
* `cargo build --features=`
