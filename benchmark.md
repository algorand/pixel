# Benchmarks
This benchmark is outdated. It will be updated with the new implementation.


This is the benchmark result for consensus signature scheme with `d = 30`.

| Function | Timing | variance | Main Component |
|---|---:|---:|---|
| g1_mul             |    0.237 ms | 14.7 % |  |
| g2_mul             |     0.841 ms |  12.8 % |  |
| pairing            |   1.931 ms |  8.4 % |  |

## PK in G2
| Function | Timing | variance | Main Component |
|---|---:|---:|---|
|ParamGen() -> pp     | 7.003 ms|  8.8 %| (d+1) g1_mul|
|KeyGen() -> pk, sk0     | 1.027 ms|  7.1 %| g1_mul + g2_mul|
|Delegate(pp, subkey, timevec)-> subkey| 0.851 ms | 36.7 % | (3 g1_mul + g2_mul)/2 |
|Sign(pp, subkey, timevec, msg) -> sig| 1.538 ms | 9.0 % | 3 g1_mul + g2_mul|
|Verify (pp, pk, timevec, msg, sig) -> bool| 3.063 ms|10.2 % | 1 g1_mul + 3 sim pairing |
|Verify_pre_pk (pp, pk, timevec, msg, sig) -> bool| 2.604 ms|10.4 % | 1 g1_mul + 2 sim pairing |

* verification time does not include __membership testing__

## PK in G1

| Function | Timing | variance | Main Component |
|---|---:|---:|---|
|ParamGen() -> pp     | 24.505 ms|  12.9 %| (d+1) g2_mul|
|KeyGen() -> pk, sk0     | 1.027 ms|  7.1 %| g1_mul + g2_mul|
|Delegate(pp, subkey, timevec)-> subkey|   1.484 ms | 37.0 % | (g1_mul + 3 g2_mul)/2 |
|Sign(pp, subkey, timevec, msg) -> sig| 2.724 ms |  16.7 % |  g1_mul + 3 g2_mul|
|Verify (pp, pk, timevec, msg, sig) -> bool|  3.731 ms| 10.6 % | 1 g2_mul + 3 sim pairing |
|Verify_pre_pk (pp, pk, timevec, msg, sig) -> bool| 3.303 ms| 7.3% | 1 g2_mul + 2 sim pairing |

* verification time does not include __membership testing__

## comparison EdDSA - libsodium

|Function| Timing| Main Component|
|---|---:|---|
|Key Gen|0.023 ms|1 mul|
|Sign|0.023 ms|1 mul|
|Verify|0.059 ms|~ 2.5 mul (?) |

A single multiplication is ~10x faster than G1_mul with bls12-381
