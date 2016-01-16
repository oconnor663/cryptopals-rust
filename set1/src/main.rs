extern crate rustc_serialize;
extern crate crypto;

use rustc_serialize::base64::FromBase64;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use std::str;
use crypto::symmetriccipher::BlockDecryptor;

const HEX_ALPHABET: &'static [u8] = b"0123456789abcdef";
const BASE64_ALPHABET: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

fn from_hex(input: &[u8]) -> Vec<u8> {
    assert!(input.len() % 2 == 0, "hex strings must be even length");
    let mut ret = Vec::new();
    for i in 0 .. input.len()/2 {
        let first_index = HEX_ALPHABET.iter().position(|b| *b == input[2*i]).unwrap() as u8;
        let second_index = HEX_ALPHABET.iter().position(|b| *b == input[2*i+1]).unwrap() as u8;
        ret.push(16 * first_index + second_index);
    }
    ret
}

fn to_hex(input: &[u8]) -> String {
    let mut ret = String::new();
    for b in input {
        ret.push_str(&format!("{:02x}", b));
    }
    ret
}

fn to_base64(bytes: &[u8]) -> String {
    let mut accumulator = 0usize;
    let mut accumulated_bits = 0;
    let mut ret = "".to_string();
    for b in bytes {
        // Add the new byte to the right side of the accumulator.
        accumulator <<= 8;
        accumulator += *b as usize;
        accumulated_bits += 8;
        while accumulated_bits >= 6 {
            // Pull characters off the left end of the accumulator.
            accumulated_bits -= 6;
            let i = accumulator >> accumulated_bits;
            ret.push(BASE64_ALPHABET[i] as char);
            accumulator %= 1 << accumulated_bits;
        }
    }
    // Handle any extra bits at the end.
    if accumulated_bits > 0 {
        let empty_bits = 6 - accumulated_bits;
        accumulator <<= empty_bits;
        ret.push(BASE64_ALPHABET[accumulator] as char);
        for _ in 0..(empty_bits/2) {
            ret.push('=');
        }
    }
    ret
}

fn challenge1() {
    // challenge 1
    let input = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let bytes = from_hex(input);
    let output = to_base64(&*bytes);
    assert!(output == expected_output);
}

fn xor(left: &[u8], right: &[u8]) -> Vec<u8> {
    assert!(left.len() == right.len());
    let mut ret = left.to_vec();
    for i in 0..left.len() {
        ret[i] ^= right[i];
    }
    ret
}

fn challenge2() {
    // challenge 2
    let xor_left = [1, 1, 1];
    let xor_right = [2, 2, 2];
    let xor_result = xor(&xor_left, &xor_right);
    assert!(xor_result == vec![3, 3, 3]);
}

fn wikipedia_str() -> Vec<u8> {
    let mut f = File::open("input/rust_wikipedia.txt").unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    buf
}

fn reference_weights() -> ByteWeights {
    make_weights(&wikipedia_str())
}

type ByteCounts = [u32; 256];

fn make_counts(buf: &[u8]) -> ByteCounts {
    let mut counts = [0; 256];
    for c in buf {
        counts[*c as usize] += 1
    }
    counts
}

type ByteWeights = [f32; 256];

fn make_weights(buf: &[u8]) -> ByteWeights {
    let counts = make_counts(buf);
    let mut normalized = [0f32; 256];
    let mag_squared: u32 = counts.iter().fold(0, |acc, x| acc + x*x);
    let mag = (mag_squared as f32).sqrt();
    for (c, count) in counts.iter().enumerate() {
        normalized[c] = *count as f32 / mag;
    }
    normalized
}

fn score_text(buf: &[u8], reference: &ByteWeights) -> f32 {
    let normalized = make_weights(buf);
    normalized.iter().enumerate()
        .map(|(c, weight)| *weight * *(reference.get(c).unwrap_or(&0f32)))
        .fold(0f32, |x, y| x + y)
}

fn decrypt_single_byte_xor(buf: &mut[u8], reference: &ByteWeights) -> (u8, f32) {
    fn xor_mut(buf: &mut[u8], key: u8) {
        for i in 0..buf.len() {
            buf[i] ^= key;
        }
    }
    let mut best_key = 0;
    let mut best_score = score_text(&buf, reference);
    // Use u16 to deal with the fact that 256 is not a valid u8 bound. Future Rust will have
    // inclusive ranges to make this easier.
    for key in 1u16..256 {
        // Use a compound key that will undo the previous round.
        let key = key as u8;
        let compound_key = key ^ (key - 1);
        // Score this version.
        xor_mut(buf, compound_key);
        let score = score_text(&buf, reference);
        if score > best_score {
            best_score = score;
            best_key = key;
        }
    }
    // Redo the best encryption.
    xor_mut(buf, 255 ^ best_key);
    (best_key, best_score)
}

fn challenge3() {
    println!("challenge 3");
    let reference = reference_weights();
    let hex_input = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let mut bytes_input = from_hex(hex_input);
    decrypt_single_byte_xor(&mut bytes_input, &reference);
    println!("decrypted result: {}", std::str::from_utf8(&bytes_input).unwrap());
}

fn challenge4() {
    println!("challenge 4");
    let reference = reference_weights();
    let mut best_score = 0f32;
    let mut best_result = vec![];
    let f = BufReader::new(File::open("input/4.txt").unwrap());
    for line in f.lines() {
        let line = line.unwrap();
        let mut bytes = from_hex(line.as_bytes());
        let (_, score) = decrypt_single_byte_xor(&mut bytes, &reference);
        if score > best_score {
            best_score = score;
            best_result = bytes;
        }
    }
    println!("decrypted result: {:?}", std::str::from_utf8(&best_result).unwrap());
}

fn encrypt_repeating_key_xor(buf: &mut[u8], key: &[u8]) {
    for i in 0..buf.len() {
        let key_byte = key[i % key.len()];
        buf[i] ^= key_byte;
    }
}

fn challenge5() {
    let input = b"Burning 'em, if you ain't quick and nimble\n\
                  I go crazy when I hear a cymbal";
    let mut buf = input.to_vec();
    encrypt_repeating_key_xor(&mut buf, b"ICE");
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a\
                    26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027\
                    630c692b20283165286326302e27282f";
    assert!(expected == to_hex(&buf));
}

fn count_bits(mut byte: u8) -> u8 {
    let mut bits = 0;
    while byte != 0 {
        if byte % 2 == 1 {
            bits += 1;
        }
        byte >>= 1;
    }
    bits
}

fn edit_distance(s1: &[u8], s2: &[u8]) -> u32 {
    assert!(s1.len() == s2.len());
    let mut bits = 0;
    for i in 0..s1.len() {
        bits += count_bits(s1[i] ^ s2[i]) as u32;
    }
    bits
}

// fn normalized_edit_distance(s1: &[u8], s2: &[u8]) -> f32 {
//     edit_distance(s1, s2) as f32 / s1.len() as f32
// }

fn decrypt_repeating_key_xor_with_len(buf: &[u8], keylen: usize, reference: &ByteWeights) -> (Vec<u8>, Vec<u8>, f32) {
    let mut key = Vec::new();
    // determine the key
    for key_index in 0..keylen {
        let mut sample = Vec::new();
        for buf_index in 0..buf.len() {
            if buf_index % keylen == key_index {
                sample.push(buf[buf_index]);
            }
        }
        let (key_byte, _) = decrypt_single_byte_xor(&mut sample, reference);
        key.push(key_byte)
    }
    // score the plaintext
    let mut copy = buf.to_vec();
    encrypt_repeating_key_xor(&mut copy, &key);
    let score = score_text(&copy, reference);
    (key, copy, score)
}

// fn normalized_distance_for_size(buf: &[u8], key_size: usize) -> f32 {
//     let first = normalized_edit_distance(&buf[0..key_size], &buf[key_size..2*key_size]);
//     let second = normalized_edit_distance(&buf[2*key_size..3*key_size], &buf[3*key_size..4*key_size]);
//     (first + second) / 2.0
// }

fn decrypt_repeating_key_xor(buf: &[u8], reference: &ByteWeights) -> (Vec<u8>, Vec<u8>) {
    let mut best_score = 0.;
    let mut best_key = Vec::new();
    let mut best_plaintext = Vec::new();
    for key_size in 2..40 {
        let (key, plaintext, score) = decrypt_repeating_key_xor_with_len(buf, key_size, &reference);
        if score > best_score {
            best_score = score;
            best_key = key;
            best_plaintext = plaintext;
        }
    }
    (best_key, best_plaintext)
}

fn read_base64_file(path: &str) -> Vec<u8> {
    let mut f = File::open(path).unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    let decoded = buf.from_base64().unwrap();
    decoded
}

fn challenge6() {
    // The suggested approach of comparing edit distances worked really poorly...
    println!("challenge 6");
    assert!(edit_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()) == 37);
    let reference = reference_weights();
    let decoded = read_base64_file("input/6.txt");
    let (key, plaintext) = decrypt_repeating_key_xor(&decoded, &reference);
    println!("The key is: '{}'", str::from_utf8(&key).unwrap());
    for line in str::from_utf8(&plaintext).unwrap().lines().take(2) {
        println!("  {}", line)
    }
}

fn decrypt_aes128_ecb(buf: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(buf.len() % 16 == 0);
    assert!(key.len() == 16);
    let dec = crypto::aessafe::AesSafe128Decryptor::new(key);
    let mut result = Vec::new();
    for i in 0..buf.len()/16 {
        let mut tmp = [0; 16];
        dec.decrypt_block(&buf[16*i..16*(i+1)], &mut tmp);
        result.extend(&tmp);
    }
    result
}

fn challenge7() {
    println!("challenge 7");
    let ciphertext = read_base64_file("input/7.txt");
    let plaintext = decrypt_aes128_ecb(&ciphertext, b"YELLOW SUBMARINE");
    for line in str::from_utf8(&plaintext).unwrap().lines().skip(2).take(2) {
        println!("  {}", line);
    }
}

fn main() {
    challenge1();
    challenge2();
    challenge3();
    challenge4();
    challenge5();
    challenge6();
    challenge7();
}
