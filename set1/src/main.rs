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
    let empty_bits = if accumulated_bits > 0 {6 - accumulated_bits} else {0};
    accumulator <<= empty_bits;
    ret.push(BASE64_ALPHABET[accumulator] as char);
    for _ in 0..(empty_bits/2) {
        ret.push('=');
    }
    ret
}

fn xor(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut ret = Vec::new();
    for i in 0..std::cmp::max(left.len(), right.len()) {
        let mut val = 0;
        if i < left.len() {
            val ^= left[i];
        }
        if i < right.len() {
            val ^= right[i];
        }
        ret.push(val);
    }
    ret
}

fn wikipedia_str() -> String {
    let mut f = File::open("input/rust_wikipedia.txt").unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    s
}

fn make_counts(s: &str) -> HashMap<char, u32> {
    let mut counts = HashMap::new();
    for c in s.chars() {
        let counter = counts.entry(c).or_insert(0);
        *counter += 1;
    }
    counts
}

fn make_frequencies(s: &str) -> HashMap<char, f32> {
    let counts = make_counts(s);
    let mut frequencies = HashMap::new();
    let total: u32 = counts.values().fold(0, |x, y| x+y);
    for (c, count) in counts {
        frequencies.insert(c, count as f32 / total as f32);
    }
    frequencies
}

fn score(s: &str, reference: &HashMap<char, f32>) -> f32 {
    let frequencies = make_frequencies(s);
    frequencies.keys()
        .map(|c| frequencies[c] * reference[c])
        .fold(0f32, |x, y| x + y)
}

fn main() {
    let input = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    println!("input {}", std::str::from_utf8(input).unwrap());
    let bytes = from_hex(input);
    let output = to_base64(&*bytes);
    println!("{}", output);

    let xor_left = [1, 1, 1];
    let xor_right = [2, 2, 2, 2];
    let xor_result = xor(&xor_left, &xor_right);
    println!("xor result: {:?}", xor_result);

    let bad_english = "qqqqqqqqqq";
    let good_english = "eeeeeeeeeeee";
    let great_english = wikipedia_str();
    let reference = make_frequencies(&great_english);
    println!("bad {}", score(bad_english, &reference));
    println!("good {}", score(good_english, &reference));
    println!("great {}", score(&great_english, &reference));
    let freq = make_frequencies(&great_english);
    println!("{:?}", make_frequencies(&great_english));
    println!("{}", freq.values().fold(0f32, |x, y| x + y));
}
