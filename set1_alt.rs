// Alternate implementation of Set 1 using libraries for serialization.

extern crate serialize;

use serialize::hex::{FromHex, ToHex};
use serialize::base64::{Config, Standard, ToBase64};

fn hex_to_base64(s: &str) -> String {
    let config = Config{
        char_set: Standard,
        pad: false,
        line_length: None,
    };
    s.from_hex().unwrap().as_slice().to_base64(config)
}

#[test]
fn test_hex_to_base64() {
    assert_eq!("TWFu".to_string(),
               hex_to_base64("4d616e"));
    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string(),
        hex_to_base64("\
49276d206b696c6c696e6720796f757220627261696e206c\
696b65206120706f69736f6e6f7573206d757368726f6f6d"));
}

fn fixed_xor(s1: &str, s2: &str) -> String {
    assert!(s1.len() == s2.len());
    let v1 = s1.from_hex().unwrap();
    let v2 = s2.from_hex().unwrap();
    let mut result = Vec::new();
    for i in range(0, v1.len()) {
        result.push(v1[i] ^ v2[i]);
    }
    result.as_slice().to_hex()
}

#[test]
fn test_fixed_xor() {
    assert_eq!("746865206b696420646f6e277420706c6179".to_string(),
               fixed_xor("1c0111001f010100061a024b53535009181c",
                         "686974207468652062756c6c277320657965"));
}
