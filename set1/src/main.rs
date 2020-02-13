fn xor(buf: &mut [u8], mask: &[u8]) {
    assert_eq!(buf.len(), mask.len());
    for (b, m) in buf.iter_mut().zip(mask.iter()) {
        *b ^= *m
    }
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

    Ok(())
}
