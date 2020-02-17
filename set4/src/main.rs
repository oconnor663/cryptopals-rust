use arrayref::array_ref;
use block_cipher_trait::BlockCipher;
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};

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

    Ok(())
}
