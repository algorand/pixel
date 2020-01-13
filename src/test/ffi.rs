// this file implements tests on the ffi operations of Pixel signature scheme

use ffi::*;

#[test]
fn test_pixel_ffi_basic() {
    let seed = "This is a very very long seed for testing";
    let msg = "message to sign";

    let _t = c_estimate_sk_size(1, c_get_depth());
    unsafe {
        // generate key pair
        let kp = c_keygen(seed.as_ptr(), seed.len());

        // check pop
        assert!(c_verify_pop(kp.pk, kp.pop));

        // sign
        let sig = c_sign_present(kp.sk, msg.as_ptr(), msg.len(), 1);

        assert!(c_verify(kp.pk, msg.as_ptr(), msg.len(), sig));

        // testing update-then-sign for present
        for j in 2..16 {
            let sk_new = c_sk_update(kp.sk, seed.as_ptr(), seed.len(), j);
            let sig = c_sign_present(sk_new, msg.as_ptr(), msg.len(), j);
            assert!(c_verify(kp.pk, msg.as_ptr(), msg.len(), sig));
        }
    }
}

#[test]
fn test_pixel_ffi_aggregation() {
    let seed1 = "This is a very very long seed for testing";
    let seed2 = "This is another very very long seed for testing";
    let msg = "message to sign";

    unsafe {
        // generate key pairs
        let kp1 = c_keygen(seed1.as_ptr(), seed1.len());
        let kp2 = c_keygen(seed2.as_ptr(), seed2.len());
        // generate signatures
        let sig1 = c_sign_present(kp1.sk, msg.as_ptr(), msg.len(), 1);
        let sig2 = c_sign_present(kp2.sk, msg.as_ptr(), msg.len(), 1);

        // aggregate then verify
        let agg_sig = c_aggregation([sig1, sig2].as_mut_ptr(), 2);
        assert!(c_verify_agg(
            [kp1.pk, kp2.pk].as_mut_ptr(),
            2,
            msg.as_ptr(),
            msg.len(),
            agg_sig
        ));
    }
}
