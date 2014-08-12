use std::io::{BufferedReader, File};
use std::collections::HashMap;
use std::cmp::min;

fn hex_to_base64(s: &str) -> String {
    let mut bi = 0u;
    let mut buffer: [u8, ..3] = [0, ..3];
    let mut left = 0u8;
    let mut b64s = String::new();
    let b64 = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
               'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
               'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
               'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
               'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
               'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
               'w', 'x', 'y', 'z', '0', '1', '2', '3',
               '4', '5', '6', '7', '8', '9', '+' ,'/'];
    for (i, c) in s.chars().enumerate() {
        let nibble = match c {
            '0' => 0, '1' => 1, '2' => 2, '3' => 3, '4' => 4, '5' => 5, '6' => 6, '7' => 7,
            '8' => 8, '9' => 9, 'a' => 10, 'b' => 11, 'c' => 12, 'd' => 13, 'e' => 14, 'f' => 15,
            _ => fail!("invalid hex character")
        };
        if i % 2 == 0 {
            left = nibble;
            continue;
        }
        buffer[bi] = left << 4 | nibble;
        bi += 1;
        if bi < 3 { continue; }
        bi = 0;
        b64s.push_char(b64[(buffer[0] >> 2) as uint]);
        b64s.push_char(b64[(buffer[0] << 6 >> 2 | buffer[1] >> 4) as uint]);
        b64s.push_char(b64[(buffer[1] << 4 >> 2 | buffer[2] >> 6) as uint]);
        b64s.push_char(b64[(buffer[2] << 2 >> 2) as uint]);
    }
    let rem = bi;
    while bi > 0 && bi < 3 {
        buffer[bi] = 0;
        bi += 1;
    }
    if rem > 0 {
        b64s.push_char(b64[(buffer[0] >> 2) as uint]);
        b64s.push_char(b64[(buffer[0] << 6 >> 2 | buffer[1] >> 4) as uint]);
    }
    if rem > 1 {
        b64s.push_char(b64[(buffer[1] << 4 >> 2 | buffer[2] >> 6) as uint]);
    }
    b64s
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

fn hex_decode(s: &str) -> Vec<u8> {
    let mut buffer = Vec::<u8>::new();
    let mut left = 0u8;
    for (i, c) in s.chars().enumerate() {
        let nibble = match c {
            '0' => 0, '1' => 1, '2' => 2, '3' => 3, '4' => 4, '5' => 5, '6' => 6, '7' => 7,
            '8' => 8, '9' => 9, 'a' => 10, 'b' => 11, 'c' => 12, 'd' => 13, 'e' => 14, 'f' => 15,
            _ => fail!("invalid hex character")
        };
        if i % 2 == 0 {
            left = nibble;
            continue;
        }
        buffer.push(left << 4 | nibble);
    }
    buffer
}

#[test]
fn test_hex_decode() {
    assert_eq!("Man", String::from_utf8(hex_decode("4d616e")).unwrap().as_slice());
}

fn hex_encode(bs: &[u8]) -> String {
    let mut s = String::new();
    let hex = ['0', '1', '2', '3', '4', '5', '6', '7',
               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
    for b in bs.iter() {
        s.push_char(hex[(b >> 4) as uint]);
        s.push_char(hex[(b << 4 >> 4) as uint]);
    }
    s
}

fn fixed_xor(s1: &str, s2: &str) -> String {
    assert!(s1.len() == s2.len());
    let v1 = hex_decode(s1);
    let v2 = hex_decode(s2);
    let mut result = Vec::new();
    for i in range(0, v1.len()) {
        result.push(v1[i] ^ v2[i]);
    }
    hex_encode(result.as_slice())
}

#[test]
fn test_fixed_xor() {
    assert_eq!("746865206b696420646f6e277420706c6179".to_string(),
               fixed_xor("1c0111001f010100061a024b53535009181c",
                         "686974207468652062756c6c277320657965"));
}

fn score_text_naive(s: &str) -> uint {
    let mut score = 0;
    for c in s.bytes() {
        if c >= 'A' as u8 && c <= 'z' as u8 {
            score += 1;
        }
    }
    score
}

fn score_text_frequency(s: &str) -> uint {
    let mut map = HashMap::<char, uint>::new();
    //for i in range ('A' as u8, 'Z' as u8 + 1) {
    //    map.insert(i as char, 0);
    //}
    for c in s.chars() {
        let ch = if c >= 'a' && c <= 'z' {
            (c as u8 - 32) as char
        } else {
            c
        };
        map.insert_or_update_with(ch, 1u, |_k, v| *v += 1);
    }
    let mut vec: Vec<(char, uint)> = map.iter().map(|(k, v)| (*k, *v)).collect();
    vec.sort_by(|&(_, n1), &(_, n2)| n2.cmp(&n1));
    let freq_string: String = vec.iter().map(|&(c, _)| c).collect();
    let ideal_string = "ETAOINSHRDLCUMWFGYPBVKJXQZ";
    freq_string.lev_distance(ideal_string)
}

// Given a hex-encoded ciphertext XOR'd against a single character, returns the key and the plaintext.
// let result = single_byte_xor_cipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
fn single_byte_xor_cipher(s: &str) -> (String, char, int) {
    let ciphertext = hex_decode(s);
    let mut best_score = 100i;
    let mut best_key = 0u8;
    let mut best_plaintext = String::new();
    for key in range(0u8, 255) {
        let mut plaintext = Vec::<u8>::new();
        for b in ciphertext.iter() {
            plaintext.push(b ^ key);
        }
        match String::from_utf8(plaintext) {
            Ok(plaintext_string) => {
                let score = score_text_frequency(plaintext_string.as_slice()) as int;
                if score < best_score {
                    best_score = score;
                    best_key = key;
                    best_plaintext = plaintext_string;
                }
            }
            Err(_) => {}
        }
    }
    (best_plaintext, best_key as char, best_score)
}

fn detect_single_character_xor(filename: &str) {
    let mut file = BufferedReader::new(File::open(&Path::new(filename)));
    let lines: Vec<String> = file.lines().map(|x| x.unwrap().as_slice().trim().to_string()).collect();
    let mut best_score = -1i;
    let mut best_plaintext = String::new();
    for line in lines.iter() {
        let (plaintext, _, score) = single_byte_xor_cipher(line.as_slice());
        println!("{}", plaintext);
        if score > best_score {
            best_score = score;
            best_plaintext = plaintext;
        }
    }
    println!("{} {}", best_score, best_plaintext);
}

fn main() {
    //let result = single_byte_xor_cipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    //println!("{}", result);
    detect_single_character_xor("4.txt");
}
