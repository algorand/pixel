# Benchmarks

This is the benchmark result for consensus signature scheme with `d = 30`.

| Function | Timing | variance | Main Component |
|---|---:|---:|---|
| g1_mul             |    0.237 ms | 14.7 % |  |
| g2_mul             |     0.841 ms |  12.8 % |  |
| pairing            |   1.931 ms |  8.4 % |  |
||||
|ParamGen() -> pp     | 7.003 ms|  8.8 %| (d+1) g1_mul|
|KeyGen() -> pk, sk0     | 1.027 ms|  7.1 %| g1_mul + g2_mul|
|Delegate(pp, subkey, timevec)-> subkey| 1.523 ms | 17.3 % | 3 g1_mul + g2_mul |
|Sign(pp, subkey, timevec, msg) -> sig| 1.538 ms | 9.0 % | 3 g1_mul + g2_mul|
|Verify (pp, pk, timevec, msg, sig) -> bool| 3.063 ms|10.2 % | 1 g1_mul + 3 sim pairing |
