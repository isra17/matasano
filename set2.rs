extern crate openssl;
extern crate serialize;

use serialize::base64::{FromBase64};
use std::io::BufferedReader;
use std::io::File;
use openssl::crypto::symm::{decrypt, AES_128_ECB};


fn xor(v1 : &[u8], v2 : &[u8]) -> Vec<u8> {
    v1.iter().zip(v2.iter()).map(|(&b1, &b2)| b1 ^ b2).collect::<Vec<u8>>()
}

fn bytes_to_string(bytes : Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => String::new()
    }
}

fn pkcs7_pad(data : &mut Vec<u8>, block_size : uint) {
    let n = block_size - (data.len() % block_size);
    data.grow(n, &(n as u8));
}

fn aes_decrypt(k : &[u8], data : &[u8]) -> Vec<u8> {
    let mut padded_data = Vec::from_slice(data);
    pkcs7_pad(&mut padded_data, 16);
    decrypt(AES_128_ECB, k, Vec::new(), padded_data.as_slice())
}

fn decrypt_aes_cbc(k : &[u8], c : &[u8], iv : &[u8]) -> Vec<u8> {
    let n = c.len()/16;
    let blocks = range(0, n).map(|i| c.slice(i*16, (i+1)*16) );
    let mut m1 = Vec::from_slice(iv);
    blocks.flat_map(|b| {
        let m = aes_decrypt(k, b);
        let xord = xor(m.as_slice(), m1.as_slice());
        m1 = Vec::from_slice(b);
        xord.move_iter()
    }).collect::<Vec<u8>>()
}

fn ch9() {
    println!("------- 9 ---------");
    let mut data = Vec::from_slice("YELLOW SUBMARINE".as_bytes());
    pkcs7_pad(&mut data, 20);
    println!("Padded data: {}", data);
    println!("Padded message: {}", bytes_to_string(data.clone()));
    assert!("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes() == data.as_slice());
}

fn ch10() {
    println!("------- 10 ---------");
    let path = Path::new("./10.txt");
    let mut file = BufferedReader::new(File::open(&path));
    let c = file.read_to_string().unwrap().as_slice().from_base64().unwrap();
    let iv : [u8, ..16] = [0, ..16];
    let k = "YELLOW SUBMARINE".as_bytes();

    let m = decrypt_aes_cbc(k, c.as_slice(), iv);
    println!("Message: {}", bytes_to_string(m));
}

fn main() {
    ch9();
    ch10();
}
