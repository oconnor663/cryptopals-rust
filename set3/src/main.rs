use arrayref::array_ref;
use block_cipher_trait::BlockCipher;
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};
use std::convert::TryInto;
use std::fmt;

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

fn random_key() -> [u8; 16] {
    let mut buf = [0; 16];
    thread_rng().fill(&mut buf);
    buf
}

static SECRET_KEY_17: Lazy<[u8; 16]> = Lazy::new(random_key);

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
    (iv, cbc_encrypt(&SECRET_KEY_17, &iv, &text))
}

fn has_valid_padding(ciphertext: &[u8], iv: &[u8; 16]) -> bool {
    cbc_decrypt(&SECRET_KEY_17, iv, ciphertext).is_ok()
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
    Ok(())
}
