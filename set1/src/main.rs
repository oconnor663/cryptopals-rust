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

    Ok(())
}
