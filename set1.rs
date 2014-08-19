extern crate serialize;
use serialize::hex::{FromHex, ToHex};
use serialize::base64::{ToBase64, STANDARD};

fn hex_to_base64(hex : &str) -> String {
    let config = STANDARD;
    hex.from_hex().unwrap().as_slice().to_base64(config)
}

fn xor(v1 : &[u8], v2 : &[u8]) -> Vec<u8> {
    v1.iter().zip(v2.iter()).map(|(b1, b2)| *b1 ^ *b2).collect::<Vec<u8>>()
}

fn ch1() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64 = hex_to_base64(hex);
    assert!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" == base64.as_slice());
}

fn ch2() {
    let v1 = "1c0111001f010100061a024b53535009181c".from_hex().unwrap();
    let v2 = "686974207468652062756c6c277320657965".from_hex().unwrap();
    let xor_vec = xor(v1.as_slice(), v2.as_slice());
    println!("{}", xor_vec);
    assert!("746865206b696420646f6e277420706c6179" == xor_vec.as_slice().to_hex().as_slice());
}

fn main() {
    ch1();
    ch2();
}
