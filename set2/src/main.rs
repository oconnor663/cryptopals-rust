use arrayref::array_ref;
use block_cipher_trait::BlockCipher;
// use std::str::from_utf8;

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
    assert!(last as usize <= block_len);
    for i in input.len() - last as usize..input.len() {
        assert_eq!(input[i], last);
    }
    &input[0..input.len() - last as usize]
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Challenge 1
    assert_eq!(
        pad(b"YELLOW SUBMARINE", 20),
        b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec()
    );

    // Challenge 2
    let bytes_10 = base64::decode(&INPUT_10.replace("\n", ""))?;
    let decrypted = cbc_decrypt(b"YELLOW SUBMARINE", &[0; 16], &bytes_10);
    let re_encrypted = cbc_encrypt(b"YELLOW SUBMARINE", &[0; 16], &decrypted);
    // println!(
    //     "=========== challenge 2 ================\n{}",
    //     from_utf8(&decrypted)?
    // );
    assert_eq!(bytes_10, re_encrypted);

    Ok(())
}
