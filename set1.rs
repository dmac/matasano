// Alternate implementation of Set 1 using libraries for serialization.
extern crate serialize;

use serialize::hex::{FromHex, ToHex};
use serialize::base64::{Config, Standard, ToBase64};

use std::io::{BufferedReader, File};

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
    assert_eq!("TWFu",
               hex_to_base64("4d616e").as_slice());
    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        hex_to_base64("\
49276d206b696c6c696e6720796f757220627261696e206c\
696b65206120706f69736f6e6f7573206d757368726f6f6d").as_slice());
}

fn fixed_xor(b: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(b.len() == key.len());
    let mut result = Vec::new();
    for i in range(0, b.len()) {
        result.push(b[i] ^ key[i]);
    }
    result
}

#[test]
fn test_fixed_xor() {
    assert_eq!("746865206b696420646f6e277420706c6179",
               fixed_xor("1c0111001f010100061a024b53535009181c".from_hex().unwrap().as_slice(),
                         "686974207468652062756c6c277320657965".from_hex().unwrap().as_slice())
               .as_slice().to_hex().as_slice());
}

fn score_text_naive(s: &str) -> uint {
    let mut score = 0;
    for c in s.chars() {
        if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == ' ' {
            score += 1;
        }
    }
    score
}

// Given a hex-encoded ciphertext XOR'd against a single character, plaintext, key, and score.
fn single_byte_xor_cipher(s: &str) -> (String, char, int) {
    let ciphertext = s.from_hex().unwrap();
    let mut best_score = -1;
    let mut best_key = 0u8;
    let mut best_plaintext = String::new();
    for key_char in range(0u8, 255) {
        let key = Vec::from_elem(ciphertext.len(), key_char);
        let plaintext = fixed_xor(ciphertext.as_slice(), key.as_slice());
        match String::from_utf8(plaintext) {
            Ok(plaintext_string) => {
                let score = score_text_naive(plaintext_string.as_slice()) as int;
                if score > best_score {
                    best_score = score;
                    best_key = key_char;
                    best_plaintext = plaintext_string;
                }
            }
            Err(_) => {}
        }
    }
    (best_plaintext, best_key as char, best_score)
}

fn detect_single_character_xor(filename: &str) -> (String, char, int) {
    let mut file = BufferedReader::new(File::open(&Path::new(filename)));
    let lines: Vec<String> = file.lines().map(|x| x.unwrap().as_slice().trim().to_string()).collect();
    let mut best_score = -1i;
    let mut best_key = 'a';
    let mut best_plaintext = String::new();
    for line in lines.iter() {
        let (plaintext, key, score) = single_byte_xor_cipher(line.as_slice().trim());
        if score > best_score {
            best_score = score;
            best_key = key;
            best_plaintext = plaintext.as_slice().trim().to_string();
        }
    }
    (best_plaintext, best_key, best_score)
}

fn repeating_key_xor(b: &[u8], key: &[u8]) -> Vec<u8> {
    let mut key_buf = Vec::new();
    let mut ki = 0;
    for _ in range(0, b.len()) {
        key_buf.push(key[ki]);
        ki = (ki + 1) % key.len();
    }
    fixed_xor(b, key_buf.as_slice())
}

#[test]
fn test_repeating_key_xor() {
    assert_eq!("\
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
               repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes(),
                                 "ICE".as_bytes()).as_slice().to_hex().as_slice());
}

fn main() {
    println!("{}", single_byte_xor_cipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"));
    println!("{}", detect_single_character_xor("4.txt"));
}
