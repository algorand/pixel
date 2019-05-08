use super::SecretKey;
use super::SubSecretKey;

use gammafunction::*;
use param::PubParam;
use rand::{ChaChaRng, SeedableRng};

impl SecretKey {
     // Hoeteck: would be good to add some explanation of what the fields are...
     // A SecretKey contains a vector of SubSecretKey's?
    pub fn init() -> Self {
        SecretKey {
            time: 1,
            ssk: Vec::new(),
        }
    }
    pub fn get_time(&self) -> u64 {
        self.time
    }
    pub fn get_sub_secretkey(&self) -> Vec<SubSecretKey> {
        self.ssk.clone()
    }

    pub fn set_time(&mut self, time: u64) {
        self.time = time;
    }

    pub fn set_sub_secretkey(&mut self, ssk: Vec<SubSecretKey>) {
        self.ssk = ssk;
    }

    pub fn delegate(&self, pp: &PubParam, time: u64, seed: &[u32; 4]) -> Self {
        // Hoeteck: does delegate mutate the current key, or return a new key? Please add a comment explaining.
        let t = GammaList::gen_list(time);
        let mut rng = ChaChaRng::from_seed(seed);

        let mut newsk: Vec<SubSecretKey> = vec![];
        let sk0 = self.ssk[0].clone();
        for e in t.get_list() {
            let ssk = sk0.subkey_delegate(&pp, e.get_time(), &mut rng);
            newsk.push(ssk);
        }
        SecretKey {
            time: time,
            ssk: newsk,
        }
    }

    // this delegation reuses the randomness for one of its child node
    // Hoeteck: how do you decide which child node to reuse randomness for? maybe add an explanation and an example?
    pub fn optimized_delegate(&self, pp: &PubParam, time: u64, seed: &[u32; 4]) -> Self {
        let newlist = GammaList::gen_list(time);
        let mut rng = ChaChaRng::from_seed(seed);
        let mut newsk: Vec<SubSecretKey> = vec![];
        let currentsk = self.clone();

        // creat a heap to store sks whose randomness
        // has been reused for its child node
        let mut timeheap: Vec<u64> = vec![];

        for t in newlist.get_list() {
            let mut flag = false;
            for i in 0..currentsk.ssk.len() {
                if t.get_time() == currentsk.ssk[i].time {
                    newsk.push(currentsk.ssk[i].clone());
                    flag = true;
                }
            }
            if flag == false {
                let sk0 = get_closest_ssk(self, t.get_time());
                if timeheap.contains(&sk0.time) {
                    // cannot reuse the randomness
                    let ssk = sk0.subkey_delegate(&pp, t.get_time(), &mut rng);
                    newsk.push(ssk);
                } else {
                    // can reuse the randomness
                    let ssk = sk0.subkey_delegate_with_reuse(t.get_time());
                    newsk.push(ssk);
                    timeheap.push(sk0.time);
                }
            }
        }
        SecretKey {
            time: time,
            ssk: newsk,
        }
    }
}

// returning the closest ssk so that the delegation cost is minimum

// Hoeteck: TODO, add a comment explaining the definition of "closest"? in length as a vector?
// it'd be good to add an example in the code.

fn get_closest_ssk(sk: &SecretKey, tar_time: u64) -> SubSecretKey {
    assert!(
        sk.time < tar_time,
        "invalid current time {} vs target time {}",
        sk.time,
        tar_time
    );
    let mut res = sk.ssk[0];
    for ssk in sk.clone().ssk {
        if ssk.time > res.time && ssk.time < tar_time {
            res = ssk;
        }
    }
    res
}
