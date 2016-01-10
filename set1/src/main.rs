use std::collections::HashMap;
use std::io::prelude::*;
use std::fs::File;

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

type ByteCounts = HashMap<u8, u64>;

fn make_counts(buf: &[u8]) -> ByteCounts {
    let mut counts = ByteCounts::new();
    for c in buf {
        let counter = counts.entry(*c).or_insert(0);
        *counter += 1;
    }
    counts
}

type ByteWeights = HashMap<u8, f64>;

fn make_weights(buf: &[u8]) -> HashMap<u8, f64> {
    let counts = make_counts(buf);
    let mut normalized = ByteWeights::new();
    let mag_squared: u64 = counts.values().fold(0, |acc, x| acc + x*x);
    let mag = (mag_squared as f64).sqrt();
    for (c, count) in counts {
        normalized.insert(c, count as f64 / mag as f64);
    }
    normalized
}

fn score_text(buf: &[u8], reference: &ByteWeights) -> f64 {
    let normalized = make_weights(buf);
    normalized.iter()
        .map(|(c, weight)| *weight * *(reference.get(c).unwrap_or(&0f64)))
        .fold(0f64, |x, y| x + y)
}

fn decrypt_single_byte_xor(buf: &[u8], reference: &ByteWeights) -> (u8, Vec<u8>) {
    let mut best_result = buf.to_vec();
    let mut best_key = 0;
    let mut best_score = score_text(&best_result, reference);
    for key in 0u16..256 {
        let key = key as u8;
        let mut result = buf.to_vec();
        for i in 0..result.len() {
            result[i] ^= key;
        }
        let score = score_text(&result, reference);
        if score > best_score {
            best_score = score;
            best_result = result;
            best_key = key;
        }
    }
    (best_key, best_result)
}

fn challenge3() {
    println!("challenge 3");
    let wikipedia = wikipedia_str();
    let reference = make_weights(&wikipedia);
    let encrypted_input = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let (key, result) = decrypt_single_byte_xor(&from_hex(encrypted_input), &reference);
    println!("decryption key: 0x{:x}", key);
    println!("decrypted result: {}", std::str::from_utf8(&result).unwrap());
}

fn main() {
    challenge1();
    challenge2();
    challenge3();
}
