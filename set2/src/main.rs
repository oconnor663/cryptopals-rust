extern crate rustc_serialize;
use rustc_serialize::base64::FromBase64;

extern crate crypto;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};

extern crate rand;
use rand::{OsRng, Rng};

use std::fs::File;
use std::io::prelude::*;
use std::collections::HashSet;
use std::collections::HashMap;

fn pad(buf: &[u8], blocksize: u8) -> Vec<u8> {
    let mut result = buf.to_vec();
    let diff = blocksize - (buf.len() as u8 % blocksize);
    for _ in 0..diff {
        result.push(diff);
    }
    result
}

fn unpad(buf: &[u8]) -> &[u8] {
    let padding_val = buf[buf.len()-1];
    let padding_start = buf.len() - padding_val as usize;
    for i in padding_start..buf.len() {
        assert_eq!(buf[i], padding_val);
    }
    return &buf[0..padding_start];
}

fn xor_into(dest: &mut [u8], mask: &[u8]) {
    assert_eq!(dest.len(), mask.len());
    for i in 0..dest.len() {
        dest[i] ^= mask[i];
    }
}

fn copy_to(dest: &mut [u8], src: &[u8]) {
    // There *must* be some idiomatic way to do this.
    assert_eq!(dest.len(), src.len());
    for i in 0..dest.len() {
        dest[i] = src[i]
    }
}

fn challenge9() {
    let input = b"YELLOW SUBMARINE";
    let padded = pad(input, 20);
    let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
    assert_eq!(expected as &[u8], &padded as &[u8]);
}

fn aes_cbc_encrypt(buf: &mut [u8], key: &[u8]) {
    let encryptor = crypto::aessafe::AesSafe128Encryptor::new(key);
    let mut last_ciphertext = [0; 16];
    let mut ciphertext_chunk = [0; 16];
    for chunk in buf.chunks_mut(16) {
        assert_eq!(chunk.len(), 16);
        xor_into(chunk, &last_ciphertext);
        encryptor.encrypt_block(&chunk, &mut ciphertext_chunk);
        copy_to(&mut last_ciphertext, &ciphertext_chunk);
        copy_to(chunk, &ciphertext_chunk);
    }
}

fn aes_cbc_decrypt(buf: &mut [u8], key: &[u8]) {
    let decryptor = crypto::aessafe::AesSafe128Decryptor::new(key);
    let mut last_ciphertext = [0; 16];
    let mut plaintext_chunk = [0; 16];
    for chunk in buf.chunks_mut(16) {
        assert_eq!(chunk.len(), 16);
        decryptor.decrypt_block(&chunk, &mut plaintext_chunk);
        xor_into(&mut plaintext_chunk, &last_ciphertext);
        copy_to(&mut last_ciphertext, chunk);
        copy_to(chunk, &plaintext_chunk);
    }
}

fn aes_ecb_encrypt(buf: &mut [u8], key: &[u8]) {
    assert!(buf.len() % 16 == 0);
    assert!(key.len() == 16);
    let enc = crypto::aessafe::AesSafe128Encryptor::new(key);
    let mut ciphertext_block = [0; 16];
    for chunk in buf.chunks_mut(16) {
        enc.encrypt_block(chunk, &mut ciphertext_block);
        copy_to(chunk, &ciphertext_block);
    }
}

fn challenge10() {
    println!("exercise 10");
    let mut f = File::open("input/10.txt").unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    let mut decoded = buf.from_base64().unwrap();
    aes_cbc_decrypt(&mut decoded, b"YELLOW SUBMARINE");
    let result_str = std::str::from_utf8(unpad(&decoded)).unwrap();
    for line in result_str.lines().take(2) {
        println!("{}", line)
    }
}

fn encryption_oracle_with_mode(input: &[u8], mode: BlockMode) -> Vec<u8> {
    let mut rng = OsRng::new().unwrap();
    let mut buf: Vec<u8> = Vec::new();
    let bytes_before = rng.gen_range(5, 11);
    for _ in 0..bytes_before {
        buf.push(rng.gen());
    }
    for i in 0..input.len() {
        buf.push(input[i]);
    }
    let bytes_after = rng.gen_range(5, 11);
    for _ in 0..bytes_after {
        buf.push(rng.gen());
    }
    let mut padded_buf = pad(&buf, 16);
    let mut key = [0; 16];
    for i in 0..key.len() {
        key[i] = rng.gen()
    }
    match mode {
        BlockMode::ECB => aes_ecb_encrypt(&mut padded_buf, &key),
        BlockMode::CBC => aes_cbc_encrypt(&mut padded_buf, &key),
    }
    return padded_buf
}

#[derive(Debug,PartialEq,Eq,Copy,Clone)]
enum BlockMode {
    ECB,
    CBC,
}

fn detect_encryption_type<F>(oracle: F) -> BlockMode
where F: FnOnce(&[u8]) -> Vec<u8> {
    let plaintext = [0; 64];
    let ciphertext = oracle(&plaintext);
    let mut blocks = HashSet::new();
    for chunk in ciphertext.chunks(16) {
        if blocks.contains(chunk) {
            return BlockMode::ECB;
        }
        blocks.insert(chunk);
    }
    BlockMode::CBC
}

fn challenge11() {
    println!("challenge 11");
    for &mode in &[BlockMode::ECB, BlockMode::CBC] {
        for _ in 0..10 {
            assert_eq!(mode, detect_encryption_type(|input| {
                encryption_oracle_with_mode(input, mode)
            }));
        }
    }
    println!("All checks passed.");
}

const INPUT12: &'static str = "\
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";

fn oracle12(input: &[u8]) -> Vec<u8> {
    let mut buf = input.to_vec();
    let suffix = INPUT12.from_base64().unwrap();
    buf.extend_from_slice(&suffix);
    let key = b"SHH don't tell!!";
    let mut padded_buf = pad(&buf, 16);
    aes_ecb_encrypt(&mut padded_buf, key);
    return padded_buf
}

fn challenge12() {
    let first_len = oracle12(b"").len();
    let second_len: usize;
    let mut scratch_input = vec![b'A'];
    loop {
        let this_len = oracle12(&scratch_input).len();
        if this_len > first_len {
            second_len = this_len;
            break
        }
        scratch_input.push(b'A');
    }
    let plaintext_len = first_len - scratch_input.len();
    let block_size = second_len - first_len;
    println!("block size: {}", block_size);
    let block_mode = detect_encryption_type(oracle12);
    println!("block mode: {:?}", block_mode);
    let mut plaintext = Vec::new();
    for i in 0..plaintext_len {
        // enough A's to put our byte of interest at the end of a block
        let input = vec![b'A'; block_size - 1 - (i % block_size)];
        let ciphertext = oracle12(&input);
        // the block our byte is at the end of
        let block_start = i - (i%block_size);
        let block_end = block_start + block_size;
        let block_of_interest = &ciphertext[block_start..block_end];
        // Now try out all possible blocks that could be.
        let mut next_byte = None;
        for candidate in 0u16..256 {
            let candidate = candidate as u8;
            let mut candidate_input;
            if plaintext.len() < block_size - 1 {
                // If we're still inside the first block of plaintext, pad the candidate input.
                candidate_input = vec![b'A'; block_size - 1 - plaintext.len()];
                candidate_input.extend_from_slice(&plaintext);
            } else {
                // Otherwise just use the end of the plaintext.
                candidate_input = plaintext[(plaintext.len()+1-block_size)..plaintext.len()].to_vec();
            }
            candidate_input.push(candidate as u8);
            let candidate_ciphertext = oracle12(&candidate_input);
            let candidate_block = &candidate_ciphertext[0..block_size];
            if candidate_block == block_of_interest {
                next_byte = Some(candidate);
                break
            }
        }
        plaintext.push(next_byte.unwrap());
    }
    print!("{}", std::str::from_utf8(&plaintext).unwrap());
}

fn parse_cookie(cookie: &str) -> HashMap<&str, &str> {
    let mut map = HashMap::new();
    for pair in cookie.split('&') {
        let mut parts = pair.split('=');
        let key = parts.next().unwrap();
        let val = parts.next().unwrap();
        map.insert(key, val);
    }
    map
}

fn profile_for(email: &str) -> String {
    let email = email.replace("&", "AND").replace("=", "EQUALS");
    return format!("email={}&uid=10&role=user", email);
}

fn challenge13() {
    println!("challenge 13");
    let profile = profile_for("steve&=foo=");
    println!("{}", profile);
    println!("{:?}", parse_cookie(&profile));
}

fn main() {
    challenge9();
    challenge10();
    challenge11();
    challenge12();
    challenge13();
}
