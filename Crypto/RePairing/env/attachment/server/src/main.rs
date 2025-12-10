use std::env;
use std::io::{self, Write};

use ark_bls12_381::{Fr, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use rand::rngs::OsRng;

use common::*;

fn read_line_trimmed() -> String {
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
    s.trim().to_string()
}

fn main() {
    let flag = env::var("FLAG")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "RCTF{test_flag}".to_string());
    let flag_len = flag.as_bytes().len();

    let (msk, mpk) = setup();
    let id = "suansuan@rois.team";
    let partial_sk = psk(id, &msk);
    let (sk, pk) = sk(id, &partial_sk, &mpk);

    let mut rng = OsRng;
    let pairing_key = ark_bls12_381::Bls12_381::pairing(
        (G1Projective::generator() * Fr::rand(&mut rng)).into_affine(),
        (h1("xorkey") * Fr::rand(&mut rng)).into_affine(),
    )
        .0;

    let ct = enc(&pk, id, pairing_key);
    let key = kdf(&pairing_key, flag_len);

    let mut encrypted_flag = flag.as_bytes().to_vec();
    xor(&mut encrypted_flag, &key);

    let (c1_hex, c2_hex, c3_hex) = hex_ct(&ct);
    let banner = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}\n",
        hex::encode(id.as_bytes()),
        hex::encode(DST),
        hex_gt(&pk.pk),
        hex_g2(&h1(id)),
        c1_hex,
        c2_hex,
        c3_hex,
        hex::encode(&encrypted_flag),
    );
    print!("{banner}");
    let _ = io::stdout().flush();

    // read <C1'>|<C2'>|<C3'>
    let line = read_line_trimmed();
    let mut parts = line.split('|');
    let (Some(x1), Some(x2), Some(x3)) = (parts.next(), parts.next(), parts.next()) else {
        println!("bad");
        return;
    };

    if parts.next().is_some() {
        println!("bad");
        return;
    }

    let c1_q = match parse_gt(x1) {
        Ok(v) => v,
        Err(_) => {
            println!("bad");
            return;
        }
    };
    let c2_q = match parse_g1(x2) {
        Ok(v) => v,
        Err(_) => {
            println!("bad");
            return;
        }
    };
    let c3_q = match parse_g2(x3) {
        Ok(v) => v,
        Err(_) => {
            println!("bad");
            return;
        }
    };

    let a2 = c2_q.into_affine();
    let a3 = c3_q.into_affine();

    if a2.is_zero() || a3.is_zero() {
        println!("bad");
        return;
    }

    if !a2.is_in_correct_subgroup_assuming_on_curve()
        || !a3.is_in_correct_subgroup_assuming_on_curve()
    {
        println!("bad");
        return;
    }

    if c1_q == ct.c1 && c2_q == ct.c2 && c3_q == ct.c3 {
        println!("no");
        return;
    }

    let shared = dec(
        &sk,
        &CT {
            c1: c1_q,
            c2: c2_q,
            c3: c3_q,
        },
    );
    let key = kdf(&shared, flag_len);
    println!("{}", hex::encode(&key));
}
