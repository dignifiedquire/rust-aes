//! Tests are based on
//! https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf Appendix F

extern crate aes;
extern crate data_encoding;

use data_encoding::HEXLOWER;
use aes::*;

fn as_vec(input: &str) -> Vec<u8> {
    HEXLOWER.decode(input.as_bytes()).unwrap()
}

#[test]
fn vec_conversion() {
    assert_eq!(
        as_vec("ffffff0100"),
        vec![255,255,255, 1, 0],
    );
}

// F.1.1       ECB-AES128.Encrypt
#[test]
fn ecb_aes_128_encrypt() {
    let key = "2b7e151628aed2a6abf7158809cf4f3c";

    let blocks = [
        [
            // Block #1
            "6bc1bee22e409f96e93d7e117393172a",
            "6bc1bee22e409f96e93d7e117393172a",
            "3ad77bb40d7a3660a89ecaf32466ef97",
            "3ad77bb40d7a3660a89ecaf32466ef97",
        ],
        [
            // Block #2
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "f5d3d58503b9699de785895a96fdbaaf",
            "f5d3d58503b9699de785895a96fdbaaf",
        ],
        [
            // Block #3
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "43b1cd7f598ece23881b00e3ed030688",
            "43b1cd7f598ece23881b00e3ed030688",
        ],
        [
            // Block #4
            "f69f2445df4f9b17ad2b417be66c3710",
            "f69f2445df4f9b17ad2b417be66c3710",
            "7b0c785e27e8ad3f8223207104725dd4",
            "7b0c785e27e8ad3f8223207104725dd4",
        ],
    ];

    let aes = AES::new(Size::AES128, Mode::ECB, as_vec(key).as_slice(), &[0u8; 16]);

    for block in blocks.iter() {
        let mut input = as_vec(block[0]);
        let output = as_vec(block[3]);

        let mut out = input.as_mut_slice();
        AES_ECB_encrypt(&aes, out);
        assert_eq!(out, output.as_slice());

        AES_ECB_decrypt(&aes, out);
        assert_eq!(out, as_vec(block[0]).as_slice());
    }
}

// F.2.1       CBC-AES128.Encrypt
#[test]
fn cbc_aes_128_encrypt() {
    let key = "2b7e151628aed2a6abf7158809cf4f3c";
    let iv = "000102030405060708090a0b0c0d0e0f";

    let blocks = [
        [
            // Block #1
            "6bc1bee22e409f96e93d7e117393172a",
            "6bc1bee22e409f96e93d7e117393172a",
            "7649abac8119b246cee98e9b12e9197d",
            "7649abac8119b246cee98e9b12e9197d",
        ],
        [
            // Block #2
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "d86421fb9f1a1eda505ee1375746972c",
            "5086cb9b507219ee95db113a917678b2",
            "5086cb9b507219ee95db113a917678b2",
        ],
        [
            // Block #3
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "604ed7ddf32efdff7020d0238b7c2a5d",
            "73bed6b8e3c1743b7116e69e22229516",
            "73bed6b8e3c1743b7116e69e22229516",
        ],
        [
            // Block #4
            "f69f2445df4f9b17ad2b417be66c3710",
            "8521f2fd3c8eef2cdc3da7e5c44ea206",
            "3ff1caa1681fac09120eca307586e1a7",
            "3ff1caa1681fac09120eca307586e1a7",
        ],
    ];

    let mut aes = AES::new(
        Size::AES128,
        Mode::CBC,
        as_vec(key).as_slice(),
        as_vec(iv).as_slice(),
    );

    for block in blocks.iter() {
        let mut input = as_vec(block[0]);
        let output = as_vec(block[3]);

        let mut out = input.as_mut_slice();
        AES_CBC_encrypt_buffer(&mut aes, out);
        assert_eq!(out, output.as_slice());
    }
}

// F.2.2       CBC-AES128.Decrypt
#[test]
fn cbc_aes_128_decrypt() {
    let key = "2b7e151628aed2a6abf7158809cf4f3c";
    let iv = "000102030405060708090a0b0c0d0e0f";

    let blocks = [
        [
            // Block #1
            "7649abac8119b246cee98e9b12e9197d",
            "7649abac8119b246cee98e9b12e9197d",
            "6bc1bee22e409f96e93d7e117393172a",
            "6bc1bee22e409f96e93d7e117393172a",
        ],
        [
            // Block #2
            "5086cb9b507219ee95db113a917678b2",
            "5086cb9b507219ee95db113a917678b2",
            "d86421fb9f1a1eda505ee1375746972c",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
        ],
        [
            // Block #3
            "73bed6b8e3c1743b7116e69e22229516",
            "73bed6b8e3c1743b7116e69e22229516",
            "604ed7ddf32efdff7020d0238b7c2a5d",
            "30c81c46a35ce411e5fbc1191a0a52ef",
        ],
        [
            // Block #4
            "3ff1caa1681fac09120eca307586e1a7",
            "3ff1caa1681fac09120eca307586e1a7",
            "8521f2fd3c8eef2cdc3da7e5c44ea206",
            "f69f2445df4f9b17ad2b417be66c3710",
        ],
    ];

    let mut aes = AES::new(
        Size::AES128,
        Mode::CBC,
        as_vec(key).as_slice(),
        as_vec(iv).as_slice(),
    );

    for block in blocks.iter() {
        let mut input = as_vec(block[0]);
        let output = as_vec(block[3]);

        let mut out = input.as_mut_slice();
        AES_CBC_decrypt_buffer(&mut aes, out);
        assert_eq!(out, output.as_slice());
    }
}

// F.5.1       CTR-AES128.Encrypt
#[test]
fn ctr_aes_128_encrypt() {
    let key = "2b7e151628aed2a6abf7158809cf4f3c";
    let iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    let blocks = [
        [
            // Block #1
            "6bc1bee22e409f96e93d7e117393172a",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "ec8cdf7398607cb0f2d21675ea9ea1e4",
            "874d6191b620e3261bef6864990db6ce",
        ],
        [
            // Block #2
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff00",
            "362b7c3c6773516318a077d7fc5073ae",
            "9806f66b7970fdff8617187bb9fffdff",
        ],
        [
            // Block #3
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff01",
            "6a2cc3787889374fbeb4c81b17ba6c44",
            "5ae4df3edbd5d35e5b4f09020db03eab",
        ],
        [
            // Block #4
            "f69f2445df4f9b17ad2b417be66c3710",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff02",
            "e89c399ff0f198c6d40a31db156cabfe",
            "1e031dda2fbe03d1792170a0f3009cee",
        ],
    ];

    let mut aes = AES::new(
        Size::AES128,
        Mode::CTR,
        as_vec(key).as_slice(),
        as_vec(iv).as_slice(),
    );

    for block in blocks.iter() {
        let mut input = as_vec(block[0]);
        let output = as_vec(block[3]);

        let mut out = input.as_mut_slice();
        AES_CTR_xcrypt_buffer(&mut aes, out);
        assert_eq!(out, output.as_slice());
    }
}

// F.5.2       CTR-AES128.Decrypt
#[test]
fn ctr_aes_128_decrypt() {
    let key = "2b7e151628aed2a6abf7158809cf4f3c";
    let iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    let blocks = [
        [
            // Block #1
            "874d6191b620e3261bef6864990db6ce",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "ec8cdf7398607cb0f2d21675ea9ea1e4",
            "6bc1bee22e409f96e93d7e117393172a",
        ],
        [
            // Block #2
            "9806f66b7970fdff8617187bb9fffdff",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff00",
            "362b7c3c6773516318a077d7fc5073ae",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
        ],
        [
            // Block #3
            "5ae4df3edbd5d35e5b4f09020db03eab",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff01",
            "6a2cc3787889374fbeb4c81b17ba6c44",
            "30c81c46a35ce411e5fbc1191a0a52ef",
        ],
        [
            // Block #4
            "1e031dda2fbe03d1792170a0f3009cee",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff02",
            "e89c399ff0f198c6d40a31db156cabfe",
            "f69f2445df4f9b17ad2b417be66c3710",
        ],
    ];

    let mut aes = AES::new(
        Size::AES128,
        Mode::CTR,
        as_vec(key).as_slice(),
        as_vec(iv).as_slice(),
    );

    for block in blocks.iter() {
        let mut input = as_vec(block[0]);
        let output = as_vec(block[3]);

        let mut out = input.as_mut_slice();
        AES_CTR_xcrypt_buffer(&mut aes, out);
        assert_eq!(out, output.as_slice());
    }
}
