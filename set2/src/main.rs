use arrayref::array_ref;
use block_cipher_trait::BlockCipher;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::str::from_utf8;

fn pad(input: &[u8], block_len: usize) -> Vec<u8> {
    let mut out = input.to_vec();
    let padding_bytes = block_len - (input.len() % block_len);
    for _ in 0..padding_bytes {
        out.push(padding_bytes as u8);
    }
    out
}

fn unpad(input: &[u8], block_len: usize) -> &[u8] {
    let last = *input.last().unwrap();
    assert!(last != 0);
    assert!(last as usize <= block_len, "invalid padding byte {}", last);
    for i in input.len() - last as usize..input.len() {
        assert_eq!(input[i], last);
    }
    &input[0..input.len() - last as usize]
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

fn ecb_encrypt(key: &[u8; 16], input: &[u8]) -> Vec<u8> {
    let mut out = pad(input, 16);
    assert_eq!(out.len() % 16, 0);
    for block in out.chunks_exact_mut(16) {
        aes128_encrypt_block(key, block);
    }
    out
}

fn ecb_decrypt(key: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    assert_eq!(ciphertext.len() % 16, 0);
    let mut padded_plaintext = ciphertext.to_vec();
    for block in padded_plaintext.chunks_exact_mut(16) {
        aes128_decrypt_block(key, block);
    }
    unpad(&padded_plaintext, 16).to_vec()
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

fn cbc_decrypt(key: &[u8; 16], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    assert_eq!(ciphertext.len() % 16, 0);
    let mut plaintext = ciphertext.to_vec();
    let mut last = *array_ref!(iv, 0, 16);
    for block in plaintext.chunks_exact_mut(16) {
        let ciphertext_copy = *array_ref!(block, 0, 16);
        aes128_decrypt_block(key, block);
        xor(block, &last);
        last = ciphertext_copy;
    }
    unpad(&plaintext, 16).to_vec()
}

const INPUT_10: &str = include_str!("../input/10.txt");

fn _random_key() -> [u8; 16] {
    let mut buf = [0; 16];
    thread_rng().fill(&mut buf);
    buf
}

fn _encryption_oracle_11(input: &[u8]) -> Vec<u8> {
    let mut random_padded = Vec::new();
    let mut rng = thread_rng();
    let pre_bytes = rng.gen_range(5, 11);
    let post_bytes = rng.gen_range(5, 11);
    for _ in 0..pre_bytes {
        random_padded.push(rng.gen());
    }
    random_padded.extend_from_slice(input);
    for _ in 0..post_bytes {
        random_padded.push(rng.gen());
    }
    let key = _random_key();
    if rng.gen() {
        println!("encrypting ECB");
        ecb_encrypt(&key, &random_padded)
    } else {
        println!("encrypting CBC");
        let iv = _random_key();
        cbc_encrypt(&key, &iv, &random_padded)
    }
}

fn detect_ecb(oracle: fn(&[u8]) -> Vec<u8>) -> bool {
    let input = vec![0; 128];
    let encrypted = oracle(&input);
    let mut last = &[][..];
    for chunk in encrypted.chunks_exact(16) {
        if !last.is_empty() && chunk == last {
            return true;
        }
        last = chunk;
    }
    false
}

const SECRET_B64_12: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

fn encryption_oracle_12(input: &[u8]) -> Vec<u8> {
    let key = b"secret key!!!!!!";
    let suffix = base64::decode(SECRET_B64_12).unwrap();
    let mut plaintext = input.to_vec();
    plaintext.extend_from_slice(&suffix);
    ecb_encrypt(&key, &plaintext)
}

fn parse_props(input: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in input.split('&') {
        let mut parts = pair.split('=');
        let key = parts.next().unwrap();
        let val = parts.next().unwrap();
        assert_eq!(parts.next(), None);
        assert!(!map.contains_key(key));
        map.insert(key.to_owned(), val.to_owned());
    }
    map
}

fn profile_for(address: &str) -> String {
    assert!(!address.contains('&'));
    assert!(!address.contains('='));
    format!("email={}&uid=10&role=user", address)
}

fn encrypt_profile_for(address: &str) -> Vec<u8> {
    let key = b"secret key!!!!!!";
    let profile = profile_for(address);
    ecb_encrypt(key, profile.as_bytes())
}

fn decrypt_profile(ciphertext: &[u8]) -> HashMap<String, String> {
    let key = b"secret key!!!!!!";
    let plaintext = ecb_decrypt(key, ciphertext);
    parse_props(from_utf8(&plaintext).unwrap())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Challenge 9
    assert_eq!(
        pad(b"YELLOW SUBMARINE", 20),
        b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec()
    );

    // Challenge 10
    let bytes_10 = base64::decode(&INPUT_10.replace("\n", ""))?;
    let decrypted = cbc_decrypt(b"YELLOW SUBMARINE", &[0; 16], &bytes_10);
    let re_encrypted = cbc_encrypt(b"YELLOW SUBMARINE", &[0; 16], &decrypted);
    // println!(
    //     "=========== challenge 10 ================\n{}",
    //     from_utf8(&decrypted)?
    // );
    assert_eq!(bytes_10, re_encrypted);

    // Challenge 11
    // if detect_ecb(_encryption_oracle_11) {
    //     println!("ECB detected");
    // } else {
    //     println!("CBC detected");
    // }

    // Challenge 12
    // detect the block size (which we know is 16)
    let first_output_len = encryption_oracle_12(b"A").len();
    for input_len in 2.. {
        let output_len = encryption_oracle_12(&vec!['A' as u8; input_len]).len();
        if output_len != first_output_len {
            let block_size = output_len - first_output_len;
            assert_eq!(block_size, 16);
            break;
        }
    }
    // detect ECB (which we already know it is)
    assert!(detect_ecb(encryption_oracle_12));
    // decrypt the SECRET_B64_12 string!
    let expected_answer_dont_look = base64::decode(SECRET_B64_12)?;
    let mut plaintext = Vec::new();
    while plaintext.len() < expected_answer_dont_look.len() {
        let prefix_len = 15 - (plaintext.len() % 16);
        let input = vec!['A' as u8; prefix_len];
        let output = encryption_oracle_12(&input);
        let mut candidate_input = input.clone();
        candidate_input.extend_from_slice(&plaintext);
        candidate_input.push(0);
        for candidate_byte in 0..=255 {
            *candidate_input.last_mut().unwrap() = candidate_byte;
            // dbg!(String::from_utf8_lossy(&candidate_input));
            assert_eq!(candidate_input.len() % 16, 0);
            let candidate_out = encryption_oracle_12(&candidate_input);
            if &output[..candidate_input.len()] == &candidate_out[..candidate_input.len()] {
                // println!("got a byte: {:?}", candidate_byte as char);
                plaintext.push(candidate_byte);
                break;
            }
        }
    }
    assert!(plaintext == expected_answer_dont_look);
    println!("===== challenge 12 =====\n{}", from_utf8(&plaintext)?);

    // Challenge 13
    let ciphertext = encrypt_profile_for("foo@bar.com");
    let out = decrypt_profile(&ciphertext);
    assert_eq!(out.get("email").unwrap(), "foo@bar.com");
    assert_eq!(out.get("uid").unwrap(), "10");
    assert_eq!(out.get("role").unwrap(), "user");
    // pick an email that makes "role=" sit right at the end of the second block.
    let role_eq_text = encrypt_profile_for("foooo@bar.com");
    let role_eq_prefix = &role_eq_text[..32];
    // pick an email that puts "admin" and then valid padding in the second block.
    let admin_text =
        encrypt_profile_for("AAAAAAAAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b");
    let admin_suffix = &admin_text[16..32];
    let mut attacker_ciphertext = role_eq_prefix.to_vec();
    attacker_ciphertext.extend_from_slice(admin_suffix);
    let attacker_out = decrypt_profile(&attacker_ciphertext);
    // dbg!(&attacker_out);
    assert_eq!(attacker_out.get("email").unwrap(), "foooo@bar.com");
    assert_eq!(attacker_out.get("uid").unwrap(), "10");
    assert_eq!(attacker_out.get("role").unwrap(), "admin");

    Ok(())
}
