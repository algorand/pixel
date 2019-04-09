use super::SecretKey;
use super::SubSecretKey;

use gammafunction::*;
use param::PubParam;
use rand::{ChaChaRng, SeedableRng};

impl SecretKey {
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
        let t = GammaList::gen_list(time);
        let mut rng = ChaChaRng::from_seed(seed);

        let mut newsk: Vec<SubSecretKey> = vec![];
        let sk0 = self.ssk[0].clone();
        for e in t.veclist {
            let ssk = sk0.subkey_delegate(&pp, e.time as u64, &mut rng);
            newsk.push(ssk);
        }
        SecretKey {
            time: time,
            ssk: newsk,
        }
    }
    pub fn optimized_delegate(&self, pp: &PubParam, time: u64, seed: &[u32; 4]) -> Self {
        let newlist = GammaList::gen_list(time);
        let mut rng = ChaChaRng::from_seed(seed);
        let mut newsk: Vec<SubSecretKey> = vec![];
        let currentsk = self.clone();
        for t in newlist.veclist {
            let mut flag = false;
            for i in 0..currentsk.ssk.len() {
                if t.time == currentsk.ssk[i].time {
                    newsk.push(currentsk.ssk[i].clone());
                    flag = true;
                }
            }
            if flag == false {
                let sk0 = get_closest_ssk(self, t.time as u64);
                let ssk = sk0.subkey_delegate(&pp, t.time as u64, &mut rng);
                newsk.push(ssk);
            }
        }
        SecretKey {
            time: time,
            ssk: newsk,
        }
    }
}

// returning the closest ssk so that the delegation cost is minimum
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
