#[cfg(test)]
use keys::{KeyPair, SecretKey};
#[cfg(test)]
use pairing::bls12_381::*;
#[cfg(test)]
use param::PubParam;
#[cfg(test)]
use pixel;
#[cfg(test)]
use rand::{ChaChaRng, Rand, Rng};
#[cfg(test)]
use sign::Signature;

#[test]
fn test_verify_level_leveled() {
    use param::CONST_D;
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = pixel::pixel_param_gen(&[
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ]);

    for i in 0..CONST_D {
        let time = 1 << i;
        let m = Fr::rand(&mut rng);
        let key = pixel::pixel_key_gen(
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sk = key.get_sk();
        let pk = key.get_pk();
        let sknew = pixel::pixel_key_update(
            &sk,
            time,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sig: Signature = pixel::pixel_sign(
            &sknew,
            time,
            &m,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let ver = pixel::pixel_verify(&pk, time, &m, &sig, &pp);
        assert_eq!(ver, true, "verification failed");
    }
}

#[test]
fn test_verify_level_rnd() {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = pixel::pixel_param_gen(&[
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ]);

    for _ in 0..1000 {
        let m = Fr::rand(&mut rng);
        let key = pixel::pixel_key_gen(
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sk = key.get_sk();
        let pk = key.get_pk();
        let time = (rng.next_u32() & 0x3FFFFFFF) as u64;
        let sknew = pixel::pixel_key_update(
            &sk,
            time,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let t: Signature = pixel::pixel_sign(
            &sknew,
            time,
            &m,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );

        let ver = pixel::pixel_verify(&pk, time, &m, &t, &pp);
        assert_eq!(ver, true, "verification failed");
    }
}

#[test]
fn test_verify_level_rnd_aggregated() {
    let mut rng = ChaChaRng::new_unseeded();
    let pp: PubParam = pixel::pixel_param_gen(&[
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
        rng.next_u32(),
    ]);
    let mut pklist: Vec<G2> = vec![];
    let mut siglist: Vec<Signature> = vec![];
    let m = Fr::rand(&mut rng);
    let time = (rng.next_u32() & 0x3FFFFFFF) as u64;;
    for _ in 0..20 {
        let key = pixel::pixel_key_gen(
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sk = key.get_sk();
        let pk = key.get_pk();
        let sknew = pixel::pixel_key_update(
            &sk,
            time,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let sig: Signature = pixel::pixel_sign(
            &sknew,
            time,
            &m,
            &[
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ],
            &pp,
        );
        let ver = pixel::pixel_verify(&pk, time, &m, &sig, &pp);
        assert_eq!(ver, true, "verification failed");
        pklist.push(pk);
        siglist.push(sig);
    }
    let agg_sig = Signature::aggregate(&siglist);
    let ver = pixel::pixel_verify_aggregated(&pklist, time, &m, &agg_sig, &pp);
    assert_eq!(ver, true, "aggregated verification failed");
}
