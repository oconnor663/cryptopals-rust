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
    let empty_bits = 6 - accumulated_bits;
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
}
