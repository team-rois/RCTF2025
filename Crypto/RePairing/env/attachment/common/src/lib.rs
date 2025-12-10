use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{hashing::{
    curve_maps::wb::WBMap,
    map_to_curve_hasher::MapToCurveBasedHasher,
    HashToCurve,
}, pairing::Pairing, CurveGroup, PrimeGroup};
use ark_ff::{field_hashers::DefaultFieldHasher, Field, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::io;

pub const DST: &[u8] = b"RCTF-H1:BLS12381G2_XMD:SHA-256_CTF_RO_v1";

pub type H2G2 = MapToCurveBasedHasher<
    G2Projective,
    DefaultFieldHasher<Sha256, 128>,
    WBMap<ark_bls12_381::g2::Config>,
>;
pub type GT = <Bls12_381 as Pairing>::TargetField;

#[derive(Clone)]
pub struct PSK {
    pub p1: G2Projective,
    pub p2: G1Projective,
}

#[derive(Clone)]
pub struct SK {
    pub s1: G2Projective,
    pub s2: G1Projective,
}

#[derive(Clone)]
pub struct PK {
    pub pk: GT,
}

#[derive(Clone)]
pub struct CT {
    pub c1: GT,
    pub c2: G1Projective,
    pub c3: G2Projective,
}

pub fn h1(id: &str) -> G2Projective {
    let h = H2G2::new(DST).expect("init");
    h.hash(id.as_bytes()).expect("h2c").into()
}

// ---- hex helpers ----

pub fn hex_g1(p: &G1Projective) -> String {
    let a: G1Affine = (*p).into_affine();
    let mut v = Vec::new();
    a.serialize_compressed(&mut v).unwrap();
    hex::encode(v)
}

pub fn hex_g2(p: &G2Projective) -> String {
    let a: G2Affine = (*p).into_affine();
    let mut v = Vec::new();
    a.serialize_compressed(&mut v).unwrap();
    hex::encode(v)
}

pub fn hex_gt(x: &GT) -> String {
    let mut v = Vec::new();
    x.serialize_compressed(&mut v).unwrap();
    hex::encode(v)
}

pub fn parse_g1(s: &str) -> io::Result<G1Projective> {
    let b = hex::decode(s)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "hex"))?;
    let a = G1Affine::deserialize_compressed(&*b)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "g1"))?;
    Ok(G1Projective::from(a))
}

pub fn parse_g2(s: &str) -> io::Result<G2Projective> {
    let b = hex::decode(s)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "hex"))?;
    let a = G2Affine::deserialize_compressed(&*b)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "g2"))?;
    Ok(G2Projective::from(a))
}

pub fn parse_gt(s: &str) -> io::Result<GT> {
    let b = hex::decode(s)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "hex"))?;
    GT::deserialize_compressed(&*b)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "gt"))
}

// ---- KDF & XOR ----

pub fn kdf(k: &GT, n: usize) -> Vec<u8> {
    let mut ser = Vec::new();
    k.serialize_compressed(&mut ser).unwrap();

    let mut out = Vec::with_capacity(n);
    let mut ctr: u32 = 0;

    while out.len() < n {
        let mut h = Sha256::new();
        h.update(b"RCTF-KDF-v1");
        h.update(&ser);
        h.update(ctr.to_be_bytes());

        let digest = h.finalize();
        let take = std::cmp::min(n - out.len(), digest.len());
        out.extend_from_slice(&digest[..take]);
        ctr = ctr.wrapping_add(1);
    }

    out
}

pub fn xor(buf: &mut [u8], mask: &[u8]) {
    for (a, b) in buf.iter_mut().zip(mask.iter()) {
        *a ^= *b;
    }
}

// ---- random non-zero scalar ----

fn random_non_zero_scalar() -> Fr {
    let mut rng = OsRng;
    loop {
        let s = Fr::rand(&mut rng);
        if !s.is_zero() {
            return s;
        }
    }
}

// ---- scheme ----

pub fn setup() -> (G2Projective, GT) {
    let mut rng = OsRng;
    let h = G2Projective::rand(&mut rng);
    let a = random_non_zero_scalar();

    let msk = h * a;
    let mpk = Bls12_381::pairing(
        G1Projective::generator().into_affine(),
        msk.into_affine(),
    )
        .0;

    (msk, mpk)
}

pub fn psk(id: &str, msk: &G2Projective) -> PSK {
    let r1 = random_non_zero_scalar();
    let q = h1(id);

    PSK {
        p1: *msk + q * r1,
        p2: G1Projective::generator() * r1,
    }
}

pub fn sk(id: &str, ps: &PSK, mpk: &GT) -> (SK, PK) {
    let xi = random_non_zero_scalar();
    let r2 = random_non_zero_scalar();
    let q = h1(id);

    let s1 = ps.p1 * xi + q * r2;
    let s2 = ps.p2 * xi + G1Projective::generator() * r2;
    let pk = mpk.pow(xi.into_bigint());

    (SK { s1, s2 }, PK { pk })
}

pub fn enc(pk: &PK, id: &str, shared_key: GT) -> CT {
    let t = random_non_zero_scalar();
    let q = h1(id);

    CT {
        c1: shared_key * pk.pk.pow(t.into_bigint()),
        c2: G1Projective::generator() * t,
        c3: q * t,
    }
}

pub fn dec(sk: &SK, ct: &CT) -> GT {
    let numerator = Bls12_381::pairing(sk.s2.into_affine(), ct.c3.into_affine()).0;
    let denominator = Bls12_381::pairing(ct.c2.into_affine(), sk.s1.into_affine()).0;
    ct.c1 * numerator * denominator.inverse().unwrap()
}

// ---- io-friendly ----

pub fn hex_ct(ct: &CT) -> (String, String, String) {
    (hex_gt(&ct.c1), hex_g1(&ct.c2), hex_g2(&ct.c3))
}
