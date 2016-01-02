const BASE64_ALPHABET: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

fn base64(bytes: &[u8]) -> String {
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

fn main() {
    let b = b"foobarba";
    println!("{:?}", String::from_utf8(b.to_vec()));
    let s = base64(b);
    println!("{}", s);
}
