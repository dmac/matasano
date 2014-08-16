extern crate serialize;
extern crate matasano;

use std::io::{BufferedReader, File};
use serialize::hex::{FromHex, ToHex};
use serialize::base64::{FromBase64};

fn check(n: uint, pass: bool) {
    println!("{}{} {}", if n < 10 { "0" } else { "" }, n, if pass { "+" } else { "-" });
}

fn challenge1() {
    let src = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let dst = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    check(1, dst == matasano::hex_to_base64(src).as_slice());
}

fn challenge2() {
    let src = "1c0111001f010100061a024b53535009181c";
    let key = "686974207468652062756c6c277320657965";
    let dst = "746865206b696420646f6e277420706c6179";
    check(2, dst == matasano::fixed_xor(src.from_hex().unwrap().as_slice(),
                                        key.from_hex().unwrap().as_slice()).as_slice().to_hex().as_slice());
}

fn challenge3() {
    let src = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let dst = "Cooking MC's like a pound of bacon";
    let (res, _, _) = matasano::decrypt_single_byte_xor(src.from_hex().unwrap().as_slice());
    check(3, dst == res.as_slice());
}

fn challenge4() {
    let mut file = BufferedReader::new(File::open(&Path::new("data/4.txt")));
    let lines: Vec<String> = file.lines().map(|x| x.unwrap().as_slice().trim().to_string()).collect();
    let mut best_score = -1i;
    let mut best_plaintext = String::new();
    for line in lines.iter() {
        let buf = line.as_slice().trim().from_hex().unwrap();
        let (plaintext, _, score) = matasano::decrypt_single_byte_xor(buf.as_slice());
        if score > best_score {
            best_score = score;
            best_plaintext = plaintext.as_slice().trim().to_string();
        }
    }
    check(4, "Now that the party is jumping" == best_plaintext.as_slice());
}

fn challenge5() {
    let src = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";
    let dst = "\
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    let res = matasano::repeating_key_xor(src.as_bytes(), key.as_bytes()).as_slice().to_hex();
    check(5, dst == res.as_slice());
}

fn challenge6() {
    let mut file = File::open(&Path::new("data/6.txt")).unwrap();
    let buf = file.read_to_end().unwrap().as_slice().from_base64().unwrap();
    let (_, key) = matasano::decrypt_repeating_key_xor(buf);
    check(6, "Terminator X: Bring the noise".as_bytes() == key.as_slice());
}

fn challenge7() {
    let mut file = File::open(&Path::new("data/7.txt")).unwrap();
    let data = file.read_to_end().unwrap().as_slice().from_base64().unwrap();
    let key = "YELLOW SUBMARINE".as_bytes();
    let res = String::from_utf8(matasano::decrypt_aes_ecb(data.as_slice(), key)).unwrap();
    let line = res.as_slice().lines().next().unwrap().trim();
    let dst = "I'm back and I'm ringin' the bell";
    check(7, dst == line);
}

fn challenge8() {
    let mut file = BufferedReader::new(File::open(&Path::new("data/8.txt")));
    let lines: Vec<Vec<u8>> = file.lines().map(|l| l.unwrap().as_slice().from_hex().unwrap()).collect();
    let line_refs: Vec<&[u8]> = lines.iter().map(|l| l.as_slice()).collect();
    let (_, i) = matasano::detect_aes_ecb(line_refs.as_slice());
    check(8, i == 132);
}

fn challenge9() {
    let src = "YELLOW SUBMARINE";
    let dst = "YELLOW SUBMARINE\x04\x04\x04\x04";
    let buf: Vec<u8> = src.bytes().collect();
    let res = String::from_utf8(matasano::pad(buf, 20)).unwrap();
    check(9, dst == res.as_slice());
}

fn challenge10() {
    let src: Vec<u8> = "one two three four five".bytes().collect();
    let key = "YELLOW SUBMARINE";
    let ecb_is_symmetric = src ==
        matasano::decrypt_aes_ecb(
            matasano::encrypt_aes_ecb(src.as_slice(), key.as_bytes()).as_slice(),
            key.as_bytes());

    let dst = "A rockin' on the mike while the fly girls yell ";
    let mut file = File::open(&Path::new("data/10.txt")).unwrap();
    let buf = file.read_to_end().unwrap().as_slice().from_base64().unwrap();
    let result = matasano::decrypt_aes_cbc(buf.as_slice(), key.as_bytes(), [0]);
    let text = String::from_utf8(result).unwrap();
    let decrypt_cbc_works = dst == text.as_slice().lines().skip(1).next().unwrap();
    check(10, ecb_is_symmetric && decrypt_cbc_works);
}

fn main() {
    challenge1();
    challenge2();
    challenge3();
    challenge4();
    challenge5();
    challenge6();
    challenge7();
    challenge8();
    challenge9();
    challenge10();
}
