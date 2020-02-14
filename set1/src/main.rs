use arrayref::array_ref;
use block_cipher_trait::BlockCipher;
use std::str::from_utf8;

fn xor(buf: &mut [u8], mask: &[u8]) {
    assert_eq!(buf.len(), mask.len());
    for (b, m) in buf.iter_mut().zip(mask.iter()) {
        *b ^= *m
    }
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

const RUST_WIKIPEDIA: &str = include_str!("../input/rust_wikipedia.txt");

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

const INPUT_4: &str = include_str!("../input/4.txt");

fn repeating_key_xor(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    for i in 0..out.len() {
        out[i] ^= key[i % key.len()];
    }
    out
}

const INPUT_6: &str = include_str!("../input/6.txt");

fn hamming_byte(b1: u8, b2: u8) -> u64 {
    (b1 ^ b2).count_ones() as u64
}

fn hamming(input1: &[u8], input2: &[u8]) -> u64 {
    assert_eq!(input1.len(), input2.len());
    input1
        .iter()
        .copied()
        .zip(input2.iter().copied())
        .map(|(a, b)| hamming_byte(a, b))
        .sum()
}

const INPUT_7: &str = include_str!("../input/7.txt");

fn aes128_ecb_decrypt(key: &[u8; 16], buf: &mut [u8]) {
    assert_eq!(buf.len() % 16, 0);
    let cipher = aes::Aes128::new(&((*key).into()));
    for chunk in buf.chunks_exact_mut(16) {
        let mut block = (*array_ref!(chunk, 0, 16)).into();
        cipher.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
}

const INPUT_8: &str = include_str!("../input/8.txt");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // challenge 1
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64_string = base64::encode(&hex::decode(hex_string)?);
    assert_eq!(
        base64_string,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );

    // challenge 2
    let mut buf = hex::decode("1c0111001f010100061a024b53535009181c")?;
    let mask = hex::decode("686974207468652062756c6c277320657965")?;
    xor(&mut buf, &mask);
    let expected = "746865206b696420646f6e277420706c6179";
    assert_eq!(expected, hex::encode(&buf));

    // challenge 3
    let bytes =
        hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
    let mut scores = Vec::new();
    for b in 0..=255 {
        let mut buf = bytes.clone();
        let mask = vec![b; buf.len()];
        xor(&mut buf, &mask);
        scores.push((score(&buf), buf));
    }
    // for (score, buf) in &scores {
    //     println!("{} {:?}", score, std::str::from_utf8(buf)?);
    // }
    let mut max_score = 0f32;
    let mut best_buf = &[][..];
    for (score, buf) in &scores {
        if *score > max_score {
            max_score = *score;
            best_buf = &buf[..];
        }
    }
    println!(
        "challenge 3: score {} {:?}",
        max_score,
        std::str::from_utf8(best_buf)?
    );

    // challenge 4
    let mut best_score = 0f32;
    let mut best_buf = Vec::new();
    let mut key = 0;
    for line in INPUT_4.split_whitespace() {
        let buf = hex::decode(line)?;
        for b in 0..=255 {
            let mut buf = buf.clone();
            let mask = vec![b; buf.len()];
            xor(&mut buf, &mask);
            let score = score(&buf);
            if score > best_score {
                best_score = score;
                best_buf = buf;
                key = b;
            }
        }
    }
    println!(
        "challenge 4: score {} key {} {:?}",
        best_score,
        key,
        std::str::from_utf8(&best_buf)?
    );

    // challenge 5
    let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    assert_eq!(
        hex::encode(&repeating_key_xor(b"ICE", input.as_bytes())),
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );

    // challenge 6
    assert_eq!(hamming(b"this is a test", b"wokka wokka!!!"), 37);
    let bytes_6 = base64::decode(&INPUT_6.replace("\n", ""))?;
    let mut best_keysize = 0;
    let mut lowest_distance = u64::max_value();
    for keysize in 2..=40 {
        let mut distance = 0;
        let mut last_chunk = &[][..];
        for chunk in bytes_6.chunks(keysize) {
            if !last_chunk.is_empty() {
                distance += hamming(&last_chunk[..chunk.len()], chunk);
            }
            last_chunk = chunk;
        }
        if distance < lowest_distance {
            lowest_distance = distance;
            best_keysize = keysize
        }
    }
    let mut key = vec![0; best_keysize];
    for key_i in 0..key.len() {
        let strided_bytes: Vec<u8> = bytes_6[key_i..]
            .iter()
            .copied()
            .step_by(key.len())
            .collect();
        let mut best_score = 0f32;
        let mut best_key_byte = 0;
        for candidate in 0..=255 {
            let mut buf = strided_bytes.clone();
            let mask = vec![candidate; buf.len()];
            xor(&mut buf, &mask);
            let score = score(&buf);
            if score > best_score {
                best_score = score;
                best_key_byte = candidate;
            }
        }
        key[key_i] = best_key_byte;
    }
    println!("challenge 6 key: {:?}", from_utf8(&key)?);
    let decrypted = repeating_key_xor(&key, &bytes_6);
    println!("{}", from_utf8(&decrypted)?);

    // Challenge 7
    let bytes_7 = base64::decode(&INPUT_7.replace("\n", ""))?;
    let mut decrypted = bytes_7.clone();
    aes128_ecb_decrypt(b"YELLOW SUBMARINE", &mut decrypted);
    println!("challenge 7");
    println!("{}", from_utf8(&decrypted)?);

    // Challenge 8
    println!("challenge 8");
    for (i, line) in INPUT_8.split_whitespace().enumerate() {
        let buf = base64::decode(line)?;
        let mut block_set = std::collections::HashSet::new();
        for chunk in buf.chunks_exact(16) {
            if block_set.contains(chunk) {
                println!("duplicate found in line {}", i);
            }
            block_set.insert(chunk);
        }
    }

    Ok(())
}
