use std::io::prelude::*;
use std::io::BufReader;
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

fn decrypt_single_byte_xor(buf: &[u8], reference: &ByteWeights) -> (u8, f32, Vec<u8>) {
    fn xor_mut(buf: &mut[u8], key: u8) {
        for i in 0..buf.len() {
            buf[i] ^= key;
        }
    }
    let mut copy = buf.to_vec();
    let mut best_key = 0;
    let mut best_score = score_text(&copy, reference);
    for key in 0u16..256 {
        let key = key as u8;
        // Encrypt the buffer.
        xor_mut(&mut copy, key);
        // Score this version.
        let score = score_text(&copy, reference);
        if score > best_score {
            best_score = score;
            best_key = key;
        }
        // Undo the encryption.
        xor_mut(&mut copy, key);
    }
    // Redo the best encryption.
    xor_mut(&mut copy, best_key);
    (best_key, best_score, copy)
}

fn challenge3() {
    println!("challenge 3");
    let wikipedia = wikipedia_str();
    let reference = make_weights(&wikipedia);
    let encrypted_input = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let (_, _, result) = decrypt_single_byte_xor(&from_hex(encrypted_input), &reference);
    println!("decrypted result: {}", std::str::from_utf8(&result).unwrap());
}

fn challenge4() {
    println!("challenge 4");
    let wikipedia = wikipedia_str();
    let reference = make_weights(&wikipedia);
    let mut best_score = 0f32;
    let mut best_result = vec![];
    let f = BufReader::new(File::open("input/4.txt").unwrap());
    for line in f.lines() {
        let line = line.unwrap();
        // println!("line: {}", line);
        let bytes = from_hex(line.as_bytes());
        let (_, score, result) = decrypt_single_byte_xor(&bytes, &reference);
        if score > best_score {
            best_score = score;
            best_result = result;
        }
    }
    println!("decrypted result: {}", std::str::from_utf8(&best_result).unwrap());
}

fn main() {
    challenge1();
    challenge2();
    challenge3();
    challenge4();
}
