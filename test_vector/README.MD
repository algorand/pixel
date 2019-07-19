# Test Vectors

This crate crates test vectors for Pixel Signatures.

## Usage

```
  cargo run
```

This will create a folder `test_vector`, and write the test vectors to this folder.
Parameters are the default parameters.
Seed for the key generation is __tentatively__ set to the string
```rust
    let seed = "this is a very long seed for pixel tests";
```
We will then use the secret key to sign a message.
The message is also __tentatively__ set to the string
```rust
    let msg = "this is the message we want pixel to sign";
```

Then, the secret key is updated from the initial stage (time stamp = 1) to
time stamp = 64, advancing 1 at a time. Signatures are also generated for those
new secret keys. Both secret keys and signatures are output for comparison.

## Format

* Plain mode: in this mode, the data are store in its debug mode (a.k.a human readable mode).
* Binary mode: in this mode, the data are serialized (using pixel's serialization function).
