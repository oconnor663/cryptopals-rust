#![allow(non_snake_case)]

use arrayref::array_ref;
use block_cipher_trait::BlockCipher;
use num_bigint::{BigUint, RandBigInt};
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};
use std::fmt;

fn random_key() -> [u8; 16] {
    let mut buf = [0; 16];
    thread_rng().fill(&mut buf);
    buf
}

static _SECRET_KEY_DONT_LOOK: Lazy<[u8; 16]> = Lazy::new(random_key);

fn modexp_u64(base: u64, pow: u64, modulus: u64) -> u64 {
    let mut result = 1;
    for _ in 0..pow {
        result = (result * base) % modulus;
    }
    result
}

fn pad(input: &[u8], block_len: usize) -> Vec<u8> {
    let mut out = input.to_vec();
    let padding_bytes = block_len - (input.len() % block_len);
    for _ in 0..padding_bytes {
        out.push(padding_bytes as u8);
    }
    out
}

#[derive(Debug)]
struct PaddingError {}

impl fmt::Display for PaddingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PaddingError")
    }
}

impl std::error::Error for PaddingError {}

fn unpad(input: &[u8]) -> Result<Vec<u8>, PaddingError> {
    let last = *input.last().unwrap();
    if last == 0 {
        return Err(PaddingError {});
    }
    if (last as usize) > input.len() {
        return Err(PaddingError {});
    }
    for i in input.len() - last as usize..input.len() {
        if input[i] != last {
            return Err(PaddingError {});
        }
    }
    Ok(input[0..input.len() - last as usize].to_vec())
}

fn aes128_encrypt_block(key: &[u8; 16], block: &mut [u8]) {
    assert_eq!(block.len(), 16);
    let mut block_array = (*array_ref!(block, 0, 16)).into();
    let cipher = aesni::Aes128::new(&((*key).into()));
    cipher.encrypt_block(&mut block_array);
    block.copy_from_slice(&block_array);
}

fn aes128_decrypt_block(key: &[u8; 16], block: &mut [u8]) {
    assert_eq!(block.len(), 16);
    let mut block_array = (*array_ref!(block, 0, 16)).into();
    let cipher = aesni::Aes128::new(&((*key).into()));
    cipher.decrypt_block(&mut block_array);
    block.copy_from_slice(&block_array);
}

fn xor(buf: &mut [u8], mask: &[u8]) {
    assert_eq!(buf.len(), mask.len());
    for (b, m) in buf.iter_mut().zip(mask.iter()) {
        *b ^= *m
    }
}

fn cbc_encrypt(key: &[u8; 16], iv: &[u8], input: &[u8]) -> Vec<u8> {
    let mut out = pad(input, 16);
    assert_eq!(out.len() % 16, 0);
    let mut last = iv;
    for block in out.chunks_exact_mut(16) {
        xor(block, last);
        aes128_encrypt_block(key, block);
        last = block;
    }
    out
}

fn cbc_decrypt(key: &[u8; 16], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PaddingError> {
    assert_eq!(ciphertext.len() % 16, 0);
    let mut plaintext = ciphertext.to_vec();
    let mut last = *array_ref!(iv, 0, 16);
    for block in plaintext.chunks_exact_mut(16) {
        let ciphertext_copy = *array_ref!(block, 0, 16);
        aes128_decrypt_block(key, block);
        xor(block, &last);
        last = ciphertext_copy;
    }
    let res = unpad(&plaintext)?;
    Ok(res)
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

    // Challenge 34
    let p = big_p;
    let g = big_g;
    // Alice generates a and A and sends A to Bob (and Eve). However, Eve is
    // going to replace A with p, before Bob gets it. (We don't represent that
    // replacement in code; we'll just use p below.)
    let a = rng.gen_biguint_range(&(0u32).into(), &p);
    let _A = g.modpow(&a, &p);
    // Likewise Bob generates b and B and transmits B, and Eve is going to swap
    // its value.
    let b = rng.gen_biguint_range(&(0u32).into(), &p);
    let _B = g.modpow(&b, &p);
    // Both Alice and Bob now use p to compute s, giving s=0;
    let s = p.modpow(&a, &p);
    assert_eq!(s, p.modpow(&b, &p));
    assert_eq!(s, 0u32.into());
    let s_hash = blake3::hash(&s.to_bytes_be());
    let s_key = array_ref!(s_hash.as_bytes(), 0, 16);
    let iv = random_key();
    let ciphertext = cbc_encrypt(s_key, &iv, b"some stuff");
    let plaintext = cbc_decrypt(s_key, &iv, &ciphertext)?;
    assert_eq!(&plaintext[..], b"some stuff");

    Ok(())
}
