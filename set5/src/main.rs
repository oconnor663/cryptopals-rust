#![allow(non_snake_case)]

use num_bigint::{BigUint, RandBigInt};
use rand::{thread_rng, Rng};

fn modexp_u64(base: u64, pow: u64, modulus: u64) -> u64 {
    let mut result = 1;
    for _ in 0..pow {
        result = (result * base) % modulus;
    }
    result
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    // Challenge 33
    let p: u64 = 37;
    let g: u64 = 37;
    let a: u64 = rng.gen_range(0, 37);
    let A = modexp_u64(g, a, p);
    let b: u64 = rng.gen_range(0, 37);
    let B = modexp_u64(g, b, p);
    assert_eq!(modexp_u64(B, a, p), modexp_u64(A, b, p));
    let big_p_hex = "
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
        fffffffffffff";
    let big_p_bytes = hex::decode(big_p_hex.replace(" ", "").replace("\n", ""))?;
    let big_p = BigUint::from_radix_be(&big_p_bytes, 256).unwrap();
    let big_g: BigUint = (2u32).into();
    let big_a = rng.gen_biguint_range(&(0u32).into(), &big_p);
    let big_A = big_g.modpow(&big_a, &big_p);
    let big_b = rng.gen_biguint_range(&(0u32).into(), &big_p);
    let big_B = big_g.modpow(&big_b, &big_p);
    assert_eq!(big_B.modpow(&big_a, &big_p), big_A.modpow(&big_b, &big_p));

    Ok(())
}
