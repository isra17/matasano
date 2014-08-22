extern crate openssl;
extern crate serialize;

use serialize::base64::{FromBase64};
use std::rand::{task_rng, Rng};
use std::io::BufferedReader;
use std::io::File;
use openssl::crypto::symm::{encrypt, decrypt, AES_128_ECB, AES_128_CBC};


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


fn gen_key() -> Vec<u8> {
    let mut key = [0u8, ..16];
    task_rng().fill_bytes(key);
    Vec::from_slice(key)
}

fn gen_random_size_vec(min : uint, max : uint) -> Vec<u8> {
    let size = task_rng().gen_range(min, max);
    let mut vec = Vec::new();
    vec.grow(size, &(0));
    task_rng().fill_bytes(vec.as_mut_slice());
    vec
}

fn crypto_service(input : &[u8]) -> Vec<u8> {
    let key = gen_key();
    let iv = gen_key();
    let prepend_bytes = gen_random_size_vec(5, 10);
    let append_bytes = gen_random_size_vec(5, 10);
    let data = prepend_bytes + input + append_bytes;
    let choices = [AES_128_ECB, AES_128_CBC];
    let t = task_rng().choose(choices).unwrap();
    println!("Used {}", (match *t { AES_128_ECB => "ECB", AES_128_CBC => "CBC", _ => "Unknown" }));
    encrypt(*t, key.as_slice(), iv, data.as_slice())
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

fn ch11() {
    for _ in range(0u32, 10u32) {
        let input = ['a' as u8, ..64];
        let data = crypto_service(input);
        if data.slice(16, 32) == data.slice(32, 48) {
            println!("Guess ECB");
        } else {
            println!("Guess CBC");
        }
    }
}

fn main() {
    ch9();
    ch10();
    ch11();
}
