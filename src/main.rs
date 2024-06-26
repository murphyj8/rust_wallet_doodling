/*#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
*/
extern crate base58;
extern crate sha2; 
extern crate ripemd;
use base58::{ToBase58, FromBase58};
use sha2::{Sha256, Digest};
//use hex::decode;
use ripemd::Ripemd160;
use pbkdf2::{pbkdf2_hmac_array};
use std::num::NonZeroU32; 


const MAIN_PRIVATE_KEY: u8 = 0x80;
const TEST_PRIVATE_KEY: u8 = 0xef;
const PRIVATE_KEY_COMPRESSED_PUBKEY: u8 = 0x01;

const MAIN_PUBKEY_HASH: u8 = 0x00;
const TEST_PUBKEY_HASH: u8 = 0x6f;

fn encode_base58(data_data_encode: &[u8]) -> String{
    data_data_encode.to_base58()
}

fn decode_base58(encoded: &str) -> Vec<u8>{
    encoded.from_base58().expect("Invalid Base58 string")
}

fn hash256(data_encode: &[u8]) -> Vec<u8>{
    let mut hasher = Sha256::new();
    hasher.update(data_encode);
    let result = hasher.finalize_reset(); 
    hasher.update(&result);
    hasher.finalize().to_vec()
}

fn hash160(data_encode: &[u8]) -> Vec<u8>{
    let mut sha256 = Sha256::new();
    sha256.update(data_encode); 
    let sha256_result = sha256.finalize(); 

    let mut ripemd160_val = Ripemd160::new(); 
    ripemd160_val.update(sha256_result);
    ripemd160_val.finalize().to_vec()
}

fn encode_base58_checksum(data: &[u8]) -> String{
    let mut extended_data = data.to_vec(); 
    let checksum = &hash256(data)[..4];
    extended_data.extend_from_slice(checksum); 
    encode_base58(&extended_data)
}

fn decode_base58_check(s: &str) -> Vec<u8> {
    let decoded = s.from_base58().expect("Invalid Base58 string");
    if decoded.len() < 4 {
        panic!("Invalid length");
    }
    let (data, checksum) = decoded.split_at(decoded.len() - 4);
    let hash = hash256(data);
    if &hash[..4] != checksum {
        panic!("Checksum does not match");
    }
    data.to_vec()
}


fn wif_to_bytes(wif: &str) -> (Vec<u8>, bool, String){
    let private_key = decode_base58_check(wif);
    let prefix = private_key[0];

    let network_prefix = match prefix{
        MAIN_PRIVATE_KEY => "main",
        TEST_PRIVATE_KEY => "test",
        _=> panic!("{} does not correspind to a mainnet or testnet address", prefix),
    };
    let (private_key, compressed) = if private_key.len() == 34 && private_key[33] == PRIVATE_KEY_COMPRESSED_PUBKEY {
        (private_key[1..33].to_vec(), true)
    } else {
        (private_key[1..].to_vec(), false)
    };
    (private_key, compressed, network_prefix.to_string())
}

fn bytes_to_wif(private_key: &[u8], prefix: &str, compressed: bool) -> Result<String, String> {
    let prefix_as_bytes = match prefix{
        "test" => TEST_PRIVATE_KEY,
        _ => MAIN_PRIVATE_KEY,
    }; 
    let mut data_to_convert = vec![prefix_as_bytes];
    data_to_convert.extend_from_slice(private_key); 
    if compressed{
        data_to_convert.push(PRIVATE_KEY_COMPRESSED_PUBKEY);
    }
    Ok(encode_base58_checksum(&data_to_convert))
}

fn public_key_to_address(public_key: &[u8], prefix: &str) -> Result<String, String> {
    let prefix_bytes = match prefix{
        "test" => TEST_PUBKEY_HASH,
        "main" => MAIN_PUBKEY_HASH,
        _ => return Err("Invalid prefix".to_string())
    };

    let len = public_key.len();
    if len != 33 && len != 65{
        return Err(format!("{} is an invalid public key", len)); 
    };

    let mut addr_to_convert = vec![prefix_bytes]; 
    addr_to_convert.extend_from_slice(&hash160(public_key)); 
    Ok(encode_base58_checksum(&addr_to_convert))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_base58() {
        let data = b"hello world";
        let encoded = encode_base58(data);
        assert_eq!(encoded, "StV1DL6CwTryKyV");
    }

    #[test]
    fn test_decode_base58() {
        let encoded = "StV1DL6CwTryKyV";
        let decoded = decode_base58(encoded);
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn test_encode_base58_checksum() {
        let data = b"hello world";
        let encoded = encode_base58_checksum(data);
        assert_eq!(encoded, "3vQB7B6MrGQZaxCuFg4oh");
    }

    #[test]
    fn test_decode_base58_checksum() {
        let encoded = "3vQB7B6MrGQZaxCuFg4oh";
        let decoded = decode_base58(encoded);
        let original_data = &decoded[..decoded.len()-4];
        assert_eq!(original_data, b"hello world");
    }

    #[test]
    fn test_public_key_to_address_testnet() {
        let public_key = hex::decode("025c4618d84db4a28fbbc4edf0937c79b36ab491f27cf4013966820f5da0102ef2").unwrap();
        let address = public_key_to_address(&public_key, "test").unwrap();
        assert_eq!(address, "mwgEWxiaMmdAAQY2mVmS6GpktSodsuPwzc");
    }

    #[test]
    fn test_public_key_to_address_mainnet() {
        let public_key = hex::decode("025c4618d84db4a28fbbc4edf0937c79b36ab491f27cf4013966820f5da0102ef2").unwrap();
        let address = public_key_to_address(&public_key, "main").unwrap();
        assert_eq!(address, "1HAHDudbYkBuPJ4R3vo4GMcS2TCvyW3qzR");
    }

}

fn main() {
    println!("Hello, world!");
    let string_to_encode = b"hello world"; 
    let encoded_string = encode_base58(string_to_encode); 
    println!("Base58 encided: {}", encoded_string);
    
    let decoded_string = decode_base58(&encoded_string); 
    match String::from_utf8(decoded_string){
        Ok(str_val) => println!("Decoded base58: {}",str_val),
        Err(e) => println!("Error: {}", e),
    }

    let encoded_string_checksum = encode_base58_checksum(string_to_encode);
    println!("Base58 checksum: {}", encoded_string_checksum);

    // testnet wif
    let wif = "cUAyVdrqL91CgA4qTzE8im1GuKVjpa5Q1qSkheBzZatNaDBnkfGc";
    let (private_key, compressed, network) = wif_to_bytes(wif);
    // back to wif
    let wif_test = bytes_to_wif(&private_key, &network, compressed).unwrap(); 
    if wif == wif_test {
        println!("wif keys equal");
    }else{
        println!("{} != {}", wif, wif_test);
    }

    let pubkey = hex::decode("025c4618d84db4a28fbbc4edf0937c79b36ab491f27cf4013966820f5da0102ef2").unwrap();
    let addr = public_key_to_address(&pubkey,&network).unwrap(); 
    if addr == "mwgEWxiaMmdAAQY2mVmS6GpktSodsuPwzc"{
        println!("addrs equal {}", addr);
    }

    let password = b"It's different when it's personal. This is not an assignment for a client. Here I discovered that it is the client who is the villain.";
    println!("{:?}", password); 
    let salt = b"I'm chocked!";
    let iters = NonZeroU32::new(1000).unwrap(); 

    //let d erived_key = pbkdf2_hmac(password, salt, iters, 32); 
    let key2 = pbkdf2_hmac_array::<Sha256, 32>(password, salt, iters.into());
    println!("key -> {}", hex::encode(key2)); 

    // bytes to wif .. cNujZ5ysw7Qu11kmQG5Xcew17ZEEvqVrnND9wGLjCpXN3TDE7RWW
    //let key_wif: String = bytes_to_wif(&key2, "test", true).unwrap(); 
    //println!("create pw in wif {}", key_wif); 
}
