use arrayref::array_ref;
use block_cipher_trait::BlockCipher;
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};

fn aes128_encrypt_block(key: &[u8; 16], block: &mut [u8]) {
    assert_eq!(block.len(), 16);
    let mut block_array = (*array_ref!(block, 0, 16)).into();
    let cipher = aesni::Aes128::new(&((*key).into()));
    cipher.encrypt_block(&mut block_array);
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

fn encrypt_userdata(data: &[u8]) -> Vec<u8> {
    assert!(!data.contains(&(';' as u8)));
    assert!(!data.contains(&('=' as u8)));
    let mut content = b"comment1=cooking%20MCs;userdata=".to_vec();
    content.extend_from_slice(data);
    content.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");
    let key = b"secret key!!!!!!";
    ctr_xor(key, &mut content);
    content
}

fn user_is_admin(ciphertext: &[u8]) -> bool {
    let key = b"secret key!!!!!!";
    let mut plaintext = ciphertext.to_vec();
    ctr_xor(key, &mut plaintext);
    String::from_utf8_lossy(&plaintext)
        .find(";admin=true;")
        .is_some()
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
    let mut ciphertext = encrypt_userdata(&[]);
    let known_plaintext =
        b"comment1=cooking%20MCs;userdata=;comment2=%20like%20a%20pound%20of%20bacon";
    let target_plaintext =
        b";admin=true;                                                              ";
    xor(&mut ciphertext, known_plaintext);
    xor(&mut ciphertext, target_plaintext);
    assert!(user_is_admin(&ciphertext));

    Ok(())
}
