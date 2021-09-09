use arrayref::array_ref;
use cipher::{BlockDecrypt, BlockEncrypt, NewBlockCipher};
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng, RngCore};
use std::convert::TryInto;
use std::fmt;
use std::str::from_utf8;

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
    let cipher = aes::Aes128::new(&((*key).into()));
    cipher.encrypt_block(&mut block_array);
    block.copy_from_slice(&block_array);
}

fn aes128_decrypt_block(key: &[u8; 16], block: &mut [u8]) {
    assert_eq!(block.len(), 16);
    let mut block_array = (*array_ref!(block, 0, 16)).into();
    let cipher = aes::Aes128::new(&((*key).into()));
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

fn random_key() -> [u8; 16] {
    let mut buf = [0; 16];
    thread_rng().fill(&mut buf);
    buf
}

static SECRET_KEY_DONT_LOOK: Lazy<[u8; 16]> = Lazy::new(random_key);

fn encrypt_some_string() -> ([u8; 16], Vec<u8>) {
    let texts = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];
    let iv = random_key();
    let text_index = rand::thread_rng().gen_range(0, texts.len());
    let text = base64::decode(&texts[text_index]).unwrap();
    (iv, cbc_encrypt(&SECRET_KEY_DONT_LOOK, &iv, &text))
}

fn has_valid_padding(ciphertext: &[u8], iv: &[u8; 16]) -> bool {
    cbc_decrypt(&SECRET_KEY_DONT_LOOK, iv, ciphertext).is_ok()
}

fn crack_block(block: &mut [u8; 16], prev_block: &[u8; 16], oracle: fn(&[u8], &[u8; 16]) -> bool) {
    // Create a two-block buffer. The second block is the one of interest. The
    // first block (of ciphertext) starts with all zeros, and we'll tweak it to
    // affect the decryption of the second block as we carry out the padding
    // oracle attack.
    let mut buf = [0; 32];
    buf[16..32].copy_from_slice(block);
    // known_bytes starts from the back of the block, so the order is
    // backwards. We'll reverse it at the end.
    let mut known_bytes = Vec::new();
    while known_bytes.len() < 16 {
        let target_padding_val = known_bytes.len() as u8 + 1;
        for i in 0..known_bytes.len() {
            buf[15 - i] = known_bytes[i] ^ target_padding_val ^ prev_block[15 - i];
        }
        let mut num_found = 0;
        let mut found_byte = 0;
        for candidate_byte in 0..=255 {
            buf[15 - known_bytes.len()] = candidate_byte;
            // The IV we give the oracle doesn't matter. It only affects the
            // decryption of the first block, which is garbage anyway.
            if oracle(&buf, &[0; 16]) {
                // We've found a mask byte that results in correct padding.
                // (This is probably the target_padding_val. If not, the
                // multiple solutions assertion will fire below.) XOR'ing
                // target_padding_val with that byte thus gives the output of
                // decryption. To get the original input byte, we then XOR that
                // with the corresponding byte from the original previous
                // block.
                found_byte =
                    candidate_byte ^ target_padding_val ^ prev_block[15 - known_bytes.len()];
                num_found += 1;
            }
        }
        assert!(num_found != 0, "no solutions found");
        if num_found > 1 {
            assert_eq!(num_found, 2);
            assert_eq!(known_bytes.len(), 0);
            // This is the first byte we're decrypting, and the bytes to its
            // left just happen to be set to make multiple padding solutions
            // possible. (Most likely, the byte immediately to the left is a 2.
            // Or there could be two 3's, etc.) Tweak the first block to change
            // this and repeat.
            buf[14] += 1;
            continue;
        }
        assert_eq!(num_found, 1, "multiple solutions found");
        known_bytes.push(found_byte);
    }
    known_bytes.reverse();
    block.copy_from_slice(&known_bytes);
}

fn ctr_xor(key: &[u8; 16], mut buf: &mut [u8]) {
    let mut counter = 0u64;
    while !buf.is_empty() {
        let mut block = [0; 16];
        block[8..16].copy_from_slice(&counter.to_le_bytes());
        aes128_encrypt_block(key, &mut block);
        let take = std::cmp::min(buf.len(), 16);
        xor(&mut buf[..take], &block[..take]);
        buf = &mut buf[take..];
        counter += 1;
    }
}

const CHALLENGE_19_INPUTS: &str = include_str!("../input/19.txt");

fn ciphertexts_19() -> Vec<Vec<u8>> {
    let mut ciphertexts = Vec::new();
    for b64_text in CHALLENGE_19_INPUTS.split_whitespace() {
        let mut buf = base64::decode(b64_text).unwrap();
        ctr_xor(&SECRET_KEY_DONT_LOOK, &mut buf);
        ciphertexts.push(buf);
    }
    ciphertexts
}

fn byte_frequencies(bytes: &[u8]) -> [f32; 256] {
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let mut frequencies = [0f32; 256];
    for i in 0..frequencies.len() {
        frequencies[i] = counts[i] as f32 / bytes.len() as f32;
    }
    frequencies
}

const RUST_WIKIPEDIA: &str = include_str!("../../set1/input/rust_wikipedia.txt");

fn wikipedia_frequencies() -> [f32; 256] {
    byte_frequencies(RUST_WIKIPEDIA.as_bytes())
}

fn magnitude(v: &[f32]) -> f32 {
    let mut m = 0f32;
    for &x in v {
        m += x * x;
    }
    m.sqrt()
}

fn normalized_dot_product(a: &[f32], b: &[f32]) -> f32 {
    assert_eq!(a.len(), b.len());
    let mut sum = 0f32;
    for i in 0..a.len() {
        sum += a[i] * b[i];
    }
    sum / magnitude(a) / magnitude(b)
}

fn score(bytes: &[u8]) -> f32 {
    let w = wikipedia_frequencies();
    let f = byte_frequencies(bytes);
    normalized_dot_product(&w, &f)
}

const F: u32 = 1812433253;
const W: u32 = 32;
const N: usize = 624;
const M: usize = 397;
const R: u32 = 31;
const A: u32 = 0x9908B0DF;
const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const B: u32 = 0x9D2C5680;
const T: u32 = 15;
const C: u32 = 0xEFC60000;
const L: u32 = 18;
const LOWER_MASK: u32 = (1 << R) - 1; // That is, the binary number of r 1's
const UPPER_MASK: u32 = !LOWER_MASK; // lowest w bits of (not lower_mask)

struct MT {
    array: [u32; N],
    index: usize,
}

impl MT {
    fn seed(seed: u32) -> Self {
        let mut array = [0; N];
        array[0] = seed;
        for i in 1..N {
            array[i] = F
                .wrapping_mul(array[i - 1] ^ (array[i - 1] >> (W - 2)))
                .wrapping_add(i as u32);
        }
        Self { array, index: N }
    }

    fn extract_number(&mut self) -> u32 {
        if self.index >= N {
            if self.index > N {
                panic!();
            }
            self.twist();
        }

        let mut y = self.array[self.index];
        y ^= (y >> U) & D;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;

        self.index += 1;
        y
    }

    fn twist(&mut self) {
        for i in 0..N - 1 {
            let x = (self.array[i] & UPPER_MASK) + (self.array[(i + 1) % N] & LOWER_MASK);
            let mut x_a = x >> 1;
            if (x % 2) != 0 {
                // lowest bit of x is 1
                x_a = x_a ^ A;
            }
            self.array[i] = self.array[(i + M) % N] ^ x_a;
        }
        self.index = 0;
    }
}

fn undo_right_shift_xor_mask(mut y: u32, shift: u32, mask: u32) -> u32 {
    // One bit at a time.
    for bit_index in 0..32 {
        if bit_index + shift < 32 {
            let bit_mask = 1 << (31 - bit_index);
            y ^= ((y & bit_mask) >> shift) & mask;
        }
    }
    y
}

#[test]
fn test_undo_right_shift_xor() {
    for shift in 1..32 {
        dbg!(shift);
        let y = 0x1fd72a03;
        let shifted = y ^ (y >> shift);
        assert_eq!(y, undo_right_shift_xor_mask(shifted, shift, !0));
    }
}

fn undo_left_shift_xor_mask(mut y: u32, shift: u32, mask: u32) -> u32 {
    // One bit at a time.
    for bit_index in (0..32).rev() {
        if bit_index >= shift {
            let bit_mask = 1 << (31 - bit_index);
            y ^= ((y & bit_mask) << shift) & mask;
        }
    }
    y
}

#[test]
fn test_undo_left_shift_xor() {
    for shift in 1..32 {
        dbg!(shift);
        let y = 0x1fd72a03;
        let shifted = y ^ (y << shift);
        assert_eq!(y, undo_left_shift_xor_mask(shifted, shift, !0));
    }
}

fn untemper(mut y: u32) -> u32 {
    // Here's what we have to undo:
    // let mut y = self.array[self.index];
    // y ^= (y >> U) & D;
    // y ^= (y << S) & B;
    // y ^= (y << T) & C;
    // y ^= y >> L;

    y = undo_right_shift_xor_mask(y, L, !0);
    y = undo_left_shift_xor_mask(y, T, C);
    y = undo_left_shift_xor_mask(y, S, B);
    y = undo_right_shift_xor_mask(y, U, D);
    y
}

fn mt_stream(seed: u32, mut buf: &mut [u8]) {
    let mut mt = MT::seed(seed);
    while !buf.is_empty() {
        let stream = mt.extract_number().to_le_bytes();
        let take = std::cmp::min(buf.len(), stream.len());
        xor(&mut buf[..take], &stream[..take]);
        buf = &mut buf[take..];
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Challenge 17
    println!("============ challenge 17 =============");
    let (iv, ciphertext) = encrypt_some_string();
    assert_eq!(ciphertext.len() % 16, 0);
    let mut plaintext = ciphertext.clone();
    let mut last_block = iv;
    for chunk in plaintext.chunks_exact_mut(16) {
        let block_copy: [u8; 16] = (*chunk).try_into().unwrap();
        crack_block(chunk.try_into().unwrap(), &last_block, has_valid_padding);
        last_block = block_copy;
    }
    let unpadded = unpad(&plaintext)?;
    println!("{:?}", String::from_utf8_lossy(&unpadded));

    // Challenge 18
    println!("============ challenge 18 =============");
    let mut buf =
        base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")?;
    ctr_xor(b"YELLOW SUBMARINE", &mut buf);
    println!("{}", from_utf8(&buf)?);

    // Challenge 19
    println!("============ challenge 19 =============");
    let ciphertexts = ciphertexts_19();
    let max_len = ciphertexts.iter().map(Vec::len).max().unwrap();
    let mut mask = Vec::new();
    for index in 0..max_len {
        let mut bytes = Vec::new();
        for c in &ciphertexts {
            if c.len() > index {
                bytes.push(c[index]);
            }
        }
        let mut best_score = 0f32;
        let mut best_byte = 0;
        for mask_byte in 0..=255 {
            let mut buf = bytes.clone();
            for b in &mut buf {
                *b ^= mask_byte;
            }
            let score = score(&buf);
            if score > best_score {
                best_score = score;
                best_byte = mask_byte;
            }
        }
        mask.push(best_byte);
    }
    for text in &ciphertexts {
        let mut buf = text.clone();
        let mask = &mask[..text.len()];
        xor(&mut buf, mask);
        println!("{:?}", String::from_utf8_lossy(&buf));
    }

    // Challenge 20 is basically the above.

    // Challenge 21
    let mut rng = MT::seed(0);
    assert_eq!(2357136044, rng.extract_number());
    assert_eq!(2546248239, rng.extract_number());
    assert_eq!(3071714933, rng.extract_number());
    assert_eq!(3626093760, rng.extract_number());

    // Challenge 22
    // Sorry I don't want to wait for this thing to sleep :)
    println!("============ challenge 22 =============");
    let output = MT::seed(dbg!(rand::thread_rng().gen_range(0, 1000))).extract_number();
    for i in 0..1000 {
        if MT::seed(i).extract_number() == output {
            println!("the secret seed is {}", i);
            break;
        }
    }

    // Challenge 23
    let mut rng = MT::seed(rand::random());
    let mut untempered = [0; N];
    for i in 0..N {
        untempered[i] = untemper(rng.extract_number());
    }
    let mut rng_clone = MT {
        array: untempered,
        index: N,
    };
    assert_eq!(rng.extract_number(), rng_clone.extract_number());
    assert_eq!(rng.extract_number(), rng_clone.extract_number());
    assert_eq!(rng.extract_number(), rng_clone.extract_number());
    assert_eq!(rng.extract_number(), rng_clone.extract_number());
    assert_eq!(rng.extract_number(), rng_clone.extract_number());

    // Challenge 24
    println!("============ challenge 24 =============");
    let mut msg = *b"this is a message with some stuff";
    eprintln!("{:?}", String::from_utf8_lossy(&msg));
    mt_stream(42, &mut msg);
    eprintln!("{:?}", String::from_utf8_lossy(&msg));
    mt_stream(42, &mut msg);
    eprintln!("{:?}", String::from_utf8_lossy(&msg));
    let mut rng = rand::thread_rng();
    let random_bytes_len = rng.gen_range(0, 100);
    let mut ciphertext = vec![0; random_bytes_len];
    rng.fill_bytes(&mut ciphertext);
    ciphertext.extend_from_slice(&['A' as u8; 14]);
    let secret_key: u32 = rng.gen_range(0, 1 << 16);
    dbg!(secret_key);
    mt_stream(secret_key, &mut ciphertext);
    // Crack the secret key.
    assert_eq!(random_bytes_len, ciphertext.len() - 14, "we know this");
    let four_byte_block_start = random_bytes_len + (4 - random_bytes_len % 4);
    let block = &ciphertext[four_byte_block_start..][..4];
    let block_num = four_byte_block_start / 4;
    let block_mask = u32::from_le_bytes(*b"AAAA");
    let block_val = u32::from_le_bytes(block.try_into().unwrap()) ^ block_mask;
    for seed in 0..(1 << 16) {
        let mut mt = MT::seed(seed);
        let mut output = 0;
        for _ in 0..block_num + 1 {
            output = mt.extract_number();
        }
        if output == block_val {
            eprintln!("discovered secret key: {}", seed);
            break;
        }
    }

    Ok(())
}
