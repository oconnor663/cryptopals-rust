extern crate rustc_serialize;
use rustc_serialize::base64::FromBase64;

extern crate crypto;
use crypto::symmetriccipher::BlockDecryptor;

use std::fs::File;
use std::io::prelude::*;

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

fn aes_cbc_decode(buf: &mut [u8], key: &[u8]) {
    let decryptor = crypto::aessafe::AesSafe128Decryptor::new(key);
    let mut last_ciphertext = [0; 16];
    let mut plaintext_chunk = [0; 16];
    for chunk in buf.chunks_mut(16) {
        decryptor.decrypt_block(&chunk, &mut plaintext_chunk);
        xor_into(&mut plaintext_chunk, &last_ciphertext);
        copy_to(&mut last_ciphertext, chunk);
        copy_to(chunk, &plaintext_chunk);
    }
}

fn challenge10() {
    println!("exercise 10");
    let mut f = File::open("input/10.txt").unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    let mut decoded = buf.from_base64().unwrap();
    aes_cbc_decode(&mut decoded, b"YELLOW SUBMARINE");
    let result_str = std::str::from_utf8(unpad(&decoded)).unwrap();
    for line in result_str.lines().take(2) {
        println!("{}", line)
    }
}

fn main() {
    challenge9();
    challenge10();
}
