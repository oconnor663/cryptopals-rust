use arrayref::array_ref;
use block_cipher_trait::BlockCipher;
use digest::Digest;
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};

pub mod md4;
pub mod sha1;
mod simd;

fn pad(input: &[u8], block_len: usize) -> Vec<u8> {
    let mut out = input.to_vec();
    let padding_bytes = block_len - (input.len() % block_len);
    for _ in 0..padding_bytes {
        out.push(padding_bytes as u8);
    }
    out
}

fn unpad(input: &[u8]) -> Result<Vec<u8>, ()> {
    let last = *input.last().unwrap();
    if last == 0 {
        return Err(());
    }
    if last as usize > input.len() {
        return Err(());
    }
    for i in input.len() - last as usize..input.len() {
        if input[i] != last {
            return Err(());
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

fn random_key() -> [u8; 16] {
    let mut buf = [0; 16];
    thread_rng().fill(&mut buf);
    buf
}

static SECRET_KEY_DONT_LOOK: Lazy<[u8; 16]> = Lazy::new(random_key);

fn ctr_xor_seek(key: &[u8; 16], mut buf: &mut [u8], starting_offset: usize) {
    let mut block_offset = starting_offset % 16;
    let mut counter = starting_offset / 16;
    while !buf.is_empty() {
        let mut block = [0; 16];
        block[8..16].copy_from_slice(&counter.to_le_bytes());
        aes128_encrypt_block(key, &mut block);
        let offset_block = &block[block_offset..];
        let take = std::cmp::min(buf.len(), offset_block.len());
        xor(&mut buf[..take], &offset_block[..take]);
        buf = &mut buf[take..];
        counter += 1;
        block_offset = 0;
    }
}

fn ctr_xor(key: &[u8; 16], buf: &mut [u8]) {
    ctr_xor_seek(key, buf, 0);
}

#[test]
fn test_ctr_xor() {
    let expected = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".as_bytes();
    let ciphertext =
        base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
            .unwrap();

    let mut buf = ciphertext.clone();
    ctr_xor(b"YELLOW SUBMARINE", &mut buf);
    assert_eq!(&buf[..], expected);

    let mut buf = ciphertext.clone();
    ctr_xor_seek(b"YELLOW SUBMARINE", &mut buf[19..39], 19);
    assert_eq!(&buf[19..39], &expected[19..39]);
}

// const CHALLENGE_25_INPUT: &str = include_str!("../input/25.txt");

fn edit(ciphertext: &mut [u8], key: &[u8; 16], offset: usize, newtext: &[u8]) {
    let slice = &mut ciphertext[offset..][..newtext.len()];
    slice.copy_from_slice(newtext);
    ctr_xor_seek(key, slice, offset);
}

fn encrypt_userdata_ctr(data: &[u8]) -> Vec<u8> {
    assert!(!data.contains(&(';' as u8)));
    assert!(!data.contains(&('=' as u8)));
    let mut content = b"comment1=cooking%20MCs;userdata=".to_vec();
    content.extend_from_slice(data);
    content.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");
    let key = b"secret key!!!!!!";
    ctr_xor(key, &mut content);
    content
}

fn user_is_admin_ctr(ciphertext: &[u8]) -> bool {
    let key = b"secret key!!!!!!";
    let mut plaintext = ciphertext.to_vec();
    ctr_xor(key, &mut plaintext);
    String::from_utf8_lossy(&plaintext)
        .find(";admin=true;")
        .is_some()
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
    unpad(&plaintext).unwrap()
}

fn encrypt_userdata_cbc_key_as_iv(data: &[u8]) -> Vec<u8> {
    assert!(!data.contains(&(';' as u8)));
    assert!(!data.contains(&('=' as u8)));
    let mut content = b"comment1=cooking%20MCs;userdata=".to_vec();
    content.extend_from_slice(data);
    content.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");
    let key = b"secret key!!!!!!";
    cbc_encrypt(key, key, &content)
}

#[derive(Debug)]
struct NonAsciiError {
    plaintext: Vec<u8>,
}

fn user_is_admin_cbc_key_as_iv(ciphertext: &[u8]) -> Result<bool, NonAsciiError> {
    let key = b"secret key!!!!!!";
    let plaintext = cbc_decrypt(key, key, ciphertext);
    for &b in &plaintext {
        if b >= 128 {
            return Err(NonAsciiError { plaintext });
        }
    }
    Ok(String::from_utf8_lossy(&plaintext)
        .find(";admin=true;")
        .is_some())
}

fn sha1_mac(key: &[u8; 16], message: &[u8]) -> [u8; 20] {
    let mut hasher = sha1::Sha1::new();
    hasher.update(key);
    hasher.update(message);
    hasher.digest().bytes()
}

fn sha1_mac_verify(key: &[u8; 16], message: &[u8], mac: &[u8; 20]) -> bool {
    let expected = sha1_mac(key, message);
    constant_time_eq::constant_time_eq(&expected, mac)
}

// SHA-1 pads the message to a multiple of 64 bytes. This padding is all zeros,
// with two additions:
// - A single 0x80 byte at the end of the message / the beginning of the
//   padding. (Really a 1-bit, but in practice all messages are complete bytes
//   rather than uneven bit lengths.)
// - The 8-byte big-endian *bit* length of the message, at the end of the
//   padding.
fn sha1_pad(message: &[u8], total_len: u64) -> Vec<u8> {
    let mut padded = message.to_vec();
    padded.push(0x80);
    let last_block_len = (total_len + 1) % 64;
    if 64 - last_block_len >= 8 {
        for _ in 0..64 - last_block_len - 8 {
            padded.push(0);
        }
    } else {
        for _ in 0..64 - last_block_len + 56 {
            padded.push(0);
        }
    }
    padded.extend_from_slice(&(total_len * 8).to_be_bytes());
    padded
}

fn md4_pad(message: &[u8], total_len: u64) -> Vec<u8> {
    let mut padded = message.to_vec();
    padded.push(0x80);
    let last_block_len = (total_len + 1) % 64;
    if 64 - last_block_len >= 8 {
        for _ in 0..64 - last_block_len - 8 {
            padded.push(0);
        }
    } else {
        for _ in 0..64 - last_block_len + 56 {
            padded.push(0);
        }
    }
    padded.extend_from_slice(&(total_len * 8).to_le_bytes());
    padded
}

fn md4_mac(key: &[u8; 16], message: &[u8]) -> [u8; 16] {
    let mut hasher = md4::Md4::new();
    hasher.input(key);
    hasher.input(message);
    hasher.result().into()
}

fn md4_mac_verify(key: &[u8; 16], message: &[u8], mac: &[u8; 16]) -> bool {
    let expected = md4_mac(key, message);
    constant_time_eq::constant_time_eq(&expected, mac)
}

fn verify_sha1_mac_sleepy(plaintext: &[u8], mac: &[u8; 20]) -> bool {
    let expected_mac = sha1_mac(&SECRET_KEY_DONT_LOOK, &plaintext);
    for (expected, found) in expected_mac.iter().copied().zip(mac.iter().copied()) {
        if expected != found {
            return false;
        } else {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    return true;
}

// this is slow, so we comment out the call
fn _challenge_31() {
    let text = b"some text I want to MAC";
    let mut mac = [0; 20];
    assert!(!verify_sha1_mac_sleepy(text, &mac));
    for i in 0..mac.len() {
        dbg!(i);
        let mut max_time = 0;
        let mut best_candidate = 0;
        for candidate in 0..=255 {
            const RUNS: usize = 3;
            // Take the minimum of a few runs. This is basically Challenge 32.
            let mut runs = [0; RUNS];
            for run in &mut runs {
                let start = std::time::Instant::now();
                mac[i] = candidate;
                verify_sha1_mac_sleepy(text, &mac);
                let end = std::time::Instant::now();
                let time = (end - start).as_nanos();
                *run = time;
            }
            let best_run = runs.iter().copied().min().unwrap();
            if best_run > max_time {
                max_time = best_run;
                best_candidate = candidate;
            }
        }
        dbg!(max_time);
        mac[i] = best_candidate;
    }
    eprintln!("got:  {:?}", &mac[..]);
    eprintln!("need: {:?}", &sha1_mac(&SECRET_KEY_DONT_LOOK, text));
    assert!(dbg!(verify_sha1_mac_sleepy(text, &mac)));
    eprintln!("challenge 31 success");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Challenge 25
    let secret_plaintext = b"some really secret stuff omgomg I hope this doesn't get out";
    let mut ciphertext = secret_plaintext.to_vec();
    ctr_xor(&SECRET_KEY_DONT_LOOK, &mut ciphertext);
    // Now decrypt the ciphertext using edit.
    let mut ciphertext_copy = ciphertext.clone();
    edit(
        &mut ciphertext_copy,
        &SECRET_KEY_DONT_LOOK,
        0,
        &vec![0; ciphertext.len()],
    );
    xor(&mut ciphertext, &ciphertext_copy);
    assert_eq!(&secret_plaintext[..], &ciphertext[..]);

    // Challenge 26
    let mut ciphertext = encrypt_userdata_ctr(&[]);
    let known_plaintext =
        b"comment1=cooking%20MCs;userdata=;comment2=%20like%20a%20pound%20of%20bacon";
    let target_plaintext =
        b";admin=true;                                                              ";
    xor(&mut ciphertext, known_plaintext);
    xor(&mut ciphertext, target_plaintext);
    assert!(user_is_admin_ctr(&ciphertext));

    // Challenge 27
    eprintln!("============ challenge 27 ===================");
    let example = encrypt_userdata_cbc_key_as_iv(&[0; 16 * 3]);
    assert!(!user_is_admin_cbc_key_as_iv(&example).unwrap());
    // We need a block that decrypts to all 0's (prior to the xor step). To get
    // that, put a plaintext block in the message that's exactly equal to the
    // ciphertext block before it. (Note that the userdata begins at offset 32,
    // a block boundary.)
    let from_chosen_plaintext = encrypt_userdata_cbc_key_as_iv(&example[16..32]);
    // Now put that block at the front of a message and decrypt it. The 0's
    // will be xor'd with the key, which should then be reported back to us,
    // because the garbling is almost guaranteed to produce bad ASCII.
    let mut chosen_ciphertext = example.clone();
    chosen_ciphertext[0..16].copy_from_slice(&from_chosen_plaintext[32..48]);
    let error = user_is_admin_cbc_key_as_iv(&chosen_ciphertext).unwrap_err();
    eprintln!(
        "the key is: {:?}",
        String::from_utf8_lossy(&error.plaintext[..16])
    );

    // Challenge 28
    assert_eq!(
        sha1_mac(&[0; 16], b""),
        [225, 41, 242, 124, 81, 3, 188, 92, 196, 75, 205, 240, 161, 94, 22, 13, 68, 80, 102, 255]
    );
    let key = random_key();
    let mac = sha1_mac(&key, b"hello world");
    assert!(!sha1_mac_verify(&random_key(), b"hello world", &mac));
    assert!(!sha1_mac_verify(&key, b"WRONG MESSAGE", &mac));

    // Challenge 29
    // Test length extension.
    let mut foo_hasher = sha1::Sha1::new();
    foo_hasher.update(b"foo");
    let foo_hash = foo_hasher.digest().bytes();
    let mut foo_extender = sha1::Sha1::from_state_bytes(&foo_hash, 3);
    foo_extender.update(b"bar");
    let extended_hash = foo_extender.digest().bytes();
    let mut total_message = sha1_pad(b"foo", 3);
    total_message.extend_from_slice(b"bar");
    let mut total_hasher = sha1::Sha1::new();
    total_hasher.update(&total_message);
    let total_hash = total_hasher.digest().bytes();
    assert_eq!(extended_hash, total_hash);
    // Attack the MAC function.
    let plaintext =
        b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let mac = sha1_mac(&SECRET_KEY_DONT_LOOK, plaintext);
    let mac_input_len = (plaintext.len() + 16) as u64;
    let mut extender = sha1::Sha1::from_state_bytes(&mac, mac_input_len);
    let suffix = b";admin=true";
    extender.update(suffix);
    let extended = extender.digest().bytes();
    let mut padded = sha1_pad(plaintext, mac_input_len);
    padded.extend_from_slice(suffix);
    assert!(sha1_mac_verify(&SECRET_KEY_DONT_LOOK, &padded, &extended));

    // Challenge 30
    // Check the MD4 implementation.
    let mut reference_hasher = md4::Md4::default();
    reference_hasher.input(b"abcdefghijklmnopqrstuvwxyz");
    let reference_hash = reference_hasher.result();
    assert_eq!(
        &reference_hash[..],
        &[215, 158, 28, 48, 138, 165, 187, 205, 238, 168, 237, 99, 223, 65, 45, 169],
        "test vector works",
    );
    // Test length extension.
    let mut foo_hasher = md4::Md4::default();
    foo_hasher.input(b"foo");
    let foo_hash = foo_hasher.result();
    let mut foo_extender = md4::Md4::from_state_bytes(&foo_hash.into(), 3);
    foo_extender.input(b"bar");
    let extended_hash = foo_extender.result();
    let mut total_message = md4_pad(b"foo", 3);
    total_message.extend_from_slice(b"bar");
    let mut total_hasher = md4::Md4::default();
    total_hasher.input(&total_message);
    let total_hash = total_hasher.result();
    assert_eq!(extended_hash, total_hash);
    // Attack the MAC function.
    let plaintext =
        b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let mac = md4_mac(&SECRET_KEY_DONT_LOOK, plaintext);
    let mac_input_len = (plaintext.len() + 16) as u64;
    let mut extender = md4::Md4::from_state_bytes(&mac, mac_input_len);
    let suffix = b";admin=true";
    extender.input(suffix);
    let extended = extender.result().into();
    let mut padded = md4_pad(plaintext, mac_input_len);
    padded.extend_from_slice(suffix);
    assert!(md4_mac_verify(&SECRET_KEY_DONT_LOOK, &padded, &extended));

    // Challenge 31
    _challenge_31();

    Ok(())
}
