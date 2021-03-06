//! Simple AES implementation.

// The number of columns comprising a state in AES. This is a constant in AES. Value=4
const NB: u8 = 4;

// nk is the number of 32 bit words in a key.
// nr is the number of rounds in AES Cipher.

const NK_256: u8 = 8;
const NR_256: u8 = 14;

const NK_192: u8 = 6;
const NR_192: u8 = 12;

const NK_128: u8 = 4;
const NR_128: u8 = 10;

pub enum Mode {
    CTR,
    CBC,
    ECB,
}

pub enum Size {
    AES128,
    AES192,
    AES256,
}

pub struct AES {
    pub size: Size,
    pub mode: Mode,
    pub round_key: [u8; 240],
    pub iv: [u8; 16],
}

static SBOX: [u8; 256] = [
    0x63,
    0x7c,
    0x77,
    0x7b,
    0xf2,
    0x6b,
    0x6f,
    0xc5,
    0x30,
    0x01,
    0x67,
    0x2b,
    0xfe,
    0xd7,
    0xab,
    0x76,
    0xca,
    0x82,
    0xc9,
    0x7d,
    0xfa,
    0x59,
    0x47,
    0xf0,
    0xad,
    0xd4,
    0xa2,
    0xaf,
    0x9c,
    0xa4,
    0x72,
    0xc0,
    0xb7,
    0xfd,
    0x93,
    0x26,
    0x36,
    0x3f,
    0xf7,
    0xcc,
    0x34,
    0xa5,
    0xe5,
    0xf1,
    0x71,
    0xd8,
    0x31,
    0x15,
    0x04,
    0xc7,
    0x23,
    0xc3,
    0x18,
    0x96,
    0x05,
    0x9a,
    0x07,
    0x12,
    0x80,
    0xe2,
    0xeb,
    0x27,
    0xb2,
    0x75,
    0x09,
    0x83,
    0x2c,
    0x1a,
    0x1b,
    0x6e,
    0x5a,
    0xa0,
    0x52,
    0x3b,
    0xd6,
    0xb3,
    0x29,
    0xe3,
    0x2f,
    0x84,
    0x53,
    0xd1,
    0x00,
    0xed,
    0x20,
    0xfc,
    0xb1,
    0x5b,
    0x6a,
    0xcb,
    0xbe,
    0x39,
    0x4a,
    0x4c,
    0x58,
    0xcf,
    0xd0,
    0xef,
    0xaa,
    0xfb,
    0x43,
    0x4d,
    0x33,
    0x85,
    0x45,
    0xf9,
    0x02,
    0x7f,
    0x50,
    0x3c,
    0x9f,
    0xa8,
    0x51,
    0xa3,
    0x40,
    0x8f,
    0x92,
    0x9d,
    0x38,
    0xf5,
    0xbc,
    0xb6,
    0xda,
    0x21,
    0x10,
    0xff,
    0xf3,
    0xd2,
    0xcd,
    0x0c,
    0x13,
    0xec,
    0x5f,
    0x97,
    0x44,
    0x17,
    0xc4,
    0xa7,
    0x7e,
    0x3d,
    0x64,
    0x5d,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4f,
    0xdc,
    0x22,
    0x2a,
    0x90,
    0x88,
    0x46,
    0xee,
    0xb8,
    0x14,
    0xde,
    0x5e,
    0x0b,
    0xdb,
    0xe0,
    0x32,
    0x3a,
    0x0a,
    0x49,
    0x06,
    0x24,
    0x5c,
    0xc2,
    0xd3,
    0xac,
    0x62,
    0x91,
    0x95,
    0xe4,
    0x79,
    0xe7,
    0xc8,
    0x37,
    0x6d,
    0x8d,
    0xd5,
    0x4e,
    0xa9,
    0x6c,
    0x56,
    0xf4,
    0xea,
    0x65,
    0x7a,
    0xae,
    0x08,
    0xba,
    0x78,
    0x25,
    0x2e,
    0x1c,
    0xa6,
    0xb4,
    0xc6,
    0xe8,
    0xdd,
    0x74,
    0x1f,
    0x4b,
    0xbd,
    0x8b,
    0x8a,
    0x70,
    0x3e,
    0xb5,
    0x66,
    0x48,
    0x03,
    0xf6,
    0x0e,
    0x61,
    0x35,
    0x57,
    0xb9,
    0x86,
    0xc1,
    0x1d,
    0x9e,
    0xe1,
    0xf8,
    0x98,
    0x11,
    0x69,
    0xd9,
    0x8e,
    0x94,
    0x9b,
    0x1e,
    0x87,
    0xe9,
    0xce,
    0x55,
    0x28,
    0xdf,
    0x8c,
    0xa1,
    0x89,
    0x0d,
    0xbf,
    0xe6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2d,
    0x0f,
    0xb0,
    0x54,
    0xbb,
    0x16,
];

static RSBOX: [u8; 256] = [
    0x52,
    0x09,
    0x6a,
    0xd5,
    0x30,
    0x36,
    0xa5,
    0x38,
    0xbf,
    0x40,
    0xa3,
    0x9e,
    0x81,
    0xf3,
    0xd7,
    0xfb,
    0x7c,
    0xe3,
    0x39,
    0x82,
    0x9b,
    0x2f,
    0xff,
    0x87,
    0x34,
    0x8e,
    0x43,
    0x44,
    0xc4,
    0xde,
    0xe9,
    0xcb,
    0x54,
    0x7b,
    0x94,
    0x32,
    0xa6,
    0xc2,
    0x23,
    0x3d,
    0xee,
    0x4c,
    0x95,
    0x0b,
    0x42,
    0xfa,
    0xc3,
    0x4e,
    0x08,
    0x2e,
    0xa1,
    0x66,
    0x28,
    0xd9,
    0x24,
    0xb2,
    0x76,
    0x5b,
    0xa2,
    0x49,
    0x6d,
    0x8b,
    0xd1,
    0x25,
    0x72,
    0xf8,
    0xf6,
    0x64,
    0x86,
    0x68,
    0x98,
    0x16,
    0xd4,
    0xa4,
    0x5c,
    0xcc,
    0x5d,
    0x65,
    0xb6,
    0x92,
    0x6c,
    0x70,
    0x48,
    0x50,
    0xfd,
    0xed,
    0xb9,
    0xda,
    0x5e,
    0x15,
    0x46,
    0x57,
    0xa7,
    0x8d,
    0x9d,
    0x84,
    0x90,
    0xd8,
    0xab,
    0x00,
    0x8c,
    0xbc,
    0xd3,
    0x0a,
    0xf7,
    0xe4,
    0x58,
    0x05,
    0xb8,
    0xb3,
    0x45,
    0x06,
    0xd0,
    0x2c,
    0x1e,
    0x8f,
    0xca,
    0x3f,
    0x0f,
    0x02,
    0xc1,
    0xaf,
    0xbd,
    0x03,
    0x01,
    0x13,
    0x8a,
    0x6b,
    0x3a,
    0x91,
    0x11,
    0x41,
    0x4f,
    0x67,
    0xdc,
    0xea,
    0x97,
    0xf2,
    0xcf,
    0xce,
    0xf0,
    0xb4,
    0xe6,
    0x73,
    0x96,
    0xac,
    0x74,
    0x22,
    0xe7,
    0xad,
    0x35,
    0x85,
    0xe2,
    0xf9,
    0x37,
    0xe8,
    0x1c,
    0x75,
    0xdf,
    0x6e,
    0x47,
    0xf1,
    0x1a,
    0x71,
    0x1d,
    0x29,
    0xc5,
    0x89,
    0x6f,
    0xb7,
    0x62,
    0x0e,
    0xaa,
    0x18,
    0xbe,
    0x1b,
    0xfc,
    0x56,
    0x3e,
    0x4b,
    0xc6,
    0xd2,
    0x79,
    0x20,
    0x9a,
    0xdb,
    0xc0,
    0xfe,
    0x78,
    0xcd,
    0x5a,
    0xf4,
    0x1f,
    0xdd,
    0xa8,
    0x33,
    0x88,
    0x07,
    0xc7,
    0x31,
    0xb1,
    0x12,
    0x10,
    0x59,
    0x27,
    0x80,
    0xec,
    0x5f,
    0x60,
    0x51,
    0x7f,
    0xa9,
    0x19,
    0xb5,
    0x4a,
    0x0d,
    0x2d,
    0xe5,
    0x7a,
    0x9f,
    0x93,
    0xc9,
    0x9c,
    0xef,
    0xa0,
    0xe0,
    0x3b,
    0x4d,
    0xae,
    0x2a,
    0xf5,
    0xb0,
    0xc8,
    0xeb,
    0xbb,
    0x3c,
    0x83,
    0x53,
    0x99,
    0x61,
    0x17,
    0x2b,
    0x04,
    0x7e,
    0xba,
    0x77,
    0xd6,
    0x26,
    0xe1,
    0x69,
    0x14,
    0x63,
    0x55,
    0x21,
    0x0c,
    0x7d,
];

// The round constant word array, rcon[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static RCON: [u8; 11] = [
    0x8d,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1b,
    0x36,
];

fn get_sbox_value(num: u8) -> u8 {
    SBOX[num as usize]
}

fn get_sbox_invert(num: u8) -> u8 {
    RSBOX[num as usize]
}

// This function produces NB(nr+1) round keys. The round keys are used in each round to decrypt the states.
fn key_expansion(nk: u8, nr: u8, round_key: &mut [u8], key: &[u8]) {
    let mut j: u8;
    let mut k: u8;
    let mut tempa = [0u8; 4]; // Used for the column/row operations

    // The first round key is the key itself.
    for i in 0..nk {
        round_key[((i * 4) + 0) as usize] = key[((i * 4) + 0) as usize];
        round_key[((i * 4) + 1) as usize] = key[((i * 4) + 1) as usize];
        round_key[((i * 4) + 2) as usize] = key[((i * 4) + 2) as usize];
        round_key[((i * 4) + 3) as usize] = key[((i * 4) + 3) as usize];
    }

    // All other round keys are found from the previous round keys.
    for i in nk..(NB * (nr + 1)) {
        k = (i - 1) * 4;
        tempa[0] = round_key[(k + 0) as usize];
        tempa[1] = round_key[(k + 1) as usize];
        tempa[2] = round_key[(k + 2) as usize];
        tempa[3] = round_key[(k + 3) as usize];

        if i % nk == 0 {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // Function RotWord()
            k = tempa[0];
            tempa[0] = tempa[1];
            tempa[1] = tempa[2];
            tempa[2] = tempa[3];
            tempa[3] = k;

            // SubWord() is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output word.

            // Function Subword()
            tempa[0] = get_sbox_value(tempa[0]);
            tempa[1] = get_sbox_value(tempa[1]);
            tempa[2] = get_sbox_value(tempa[2]);
            tempa[3] = get_sbox_value(tempa[3]);

            tempa[0] = tempa[0] ^ RCON[(i / nk) as usize];
        }

        if i % nk == 4 {
            // Function Subword()
            tempa[0] = get_sbox_value(tempa[0]);
            tempa[1] = get_sbox_value(tempa[1]);
            tempa[2] = get_sbox_value(tempa[2]);
            tempa[3] = get_sbox_value(tempa[3]);
        }

        j = i * 4;
        k = (i - nk) * 4;
        round_key[(j + 0) as usize] = round_key[(k + 0) as usize] ^ tempa[0];
        round_key[(j + 1) as usize] = round_key[(k + 1) as usize] ^ tempa[1];
        round_key[(j + 2) as usize] = round_key[(k + 2) as usize] ^ tempa[2];
        round_key[(j + 3) as usize] = round_key[(k + 3) as usize] ^ tempa[3];
    }
}

impl AES {
    pub fn new(size: Size, mode: Mode, key: &[u8], iv_raw: &[u8]) -> AES {
        let mut round_key = [0u8; 240];
        match size {
            Size::AES128 => key_expansion(NK_128, NR_128, &mut round_key, key),
            Size::AES192 => key_expansion(NK_192, NR_192, &mut round_key, key),
            Size::AES256 => key_expansion(NK_256, NR_256, &mut round_key, key),
        };

        let mut iv = [0u8; 16];
        iv.clone_from_slice(iv_raw);
        AES {
            mode: mode,
            size: size,
            round_key: round_key,
            iv: iv,
        }
    }

    pub fn set_iv(&mut self, iv_raw: &[u8]) {
        self.iv.clone_from_slice(iv_raw);
    }

    pub fn nr(&self) -> u8 {
        match self.size {
            Size::AES128 => NR_128,
            Size::AES192 => NR_192,
            Size::AES256 => NR_256,
        }
    }

    pub fn nk(&self) -> u8 {
        match self.size {
            Size::AES128 => NK_128,
            Size::AES192 => NK_192,
            Size::AES256 => NK_256,
        }
    }
}


// This function adds the round key to state.
// The round key is added to the state by an XOR function.
fn add_round_key(round: u8, state: &mut [u8], round_key: &[u8]) {
    for i in 0..4u8 {
        for j in 0..4u8 {
            state[(i * 4 + j) as usize] ^= round_key[((round * NB * 4) + (i * NB) + j) as usize];
        }
    }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
fn sub_bytes(state: &mut [u8]) {
    for i in 0..4 {
        for j in 0..4 {
            state[j * 4 + i] = get_sbox_value(state[j * 4 + i]);
        }
    }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
fn shift_rows(state: &mut [u8]) {
    // Rotate first row 1 columns to left
    let mut temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Rotate second row 2 columns to left
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;

    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Rotate third row 3 columns to left
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

#[inline]
fn xtime(x: u8) -> u8 {
    ((x << 1) ^ (((x >> 7) & 1) * 0x1b))
}

// MixColumns function mixes the columns of the state matrix
fn mix_columns(state: &mut [u8]) {
    let mut tmp: u8;
    let mut tm: u8;
    let mut t: u8;

    for i in 0..4 {
        t = state[i * 4];
        tmp = state[i * 4] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3];
        tm = state[i * 4] ^ state[i * 4 + 1];
        tm = xtime(tm);

        state[i * 4] ^= tm ^ tmp;
        tm = state[i * 4 + 1] ^ state[i * 4 + 2];
        tm = xtime(tm);

        state[i * 4 + 1] ^= tm ^ tmp;
        tm = state[i * 4 + 2] ^ state[i * 4 + 3];
        tm = xtime(tm);

        state[i * 4 + 2] ^= tm ^ tmp;
        tm = state[i * 4 + 3] ^ t;
        tm = xtime(tm);

        state[i * 4 + 3] ^= tm ^ tmp;
    }
}

// Multiply is used to multiply numbers in the field GF(2^8)
fn multiply(x: u8, y: u8) -> u8 {
    (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ ((y >> 2 & 1) * xtime(xtime(x))) ^
         ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
         ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))))
}

// InvMixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
fn inv_mix_columns(state: &mut [u8]) {
    let mut a: u8;
    let mut b: u8;
    let mut c: u8;
    let mut d: u8;

    for i in 0..4 {
        a = state[i * 4];
        b = state[i * 4 + 1];
        c = state[i * 4 + 2];
        d = state[i * 4 + 3];

        state[i * 4] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^
            multiply(d, 0x09);
        state[i * 4 + 1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^
            multiply(d, 0x0d);
        state[i * 4 + 2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^
            multiply(d, 0x0b);
        state[i * 4 + 3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^
            multiply(d, 0x0e);
    }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
fn inv_sub_bytes(state: &mut [u8]) {
    for i in 0..4 {
        for j in 0..4 {
            state[j * 4 + i] = get_sbox_invert(state[j * 4 + i]);
        }
    }
}

fn inv_shift_rows(state: &mut [u8]) {
    let mut temp: u8;

    // Rotate first row 1 columns to right
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // Rotate second row 2 columns to right
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;

    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Rotate third row 3 columns to right
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// Cipher is the main function that encrypts the PlainText.
fn cipher(nr: u8, state: &mut [u8], round_key: &[u8]) {
    // Add the First round key to the state before starting the rounds.
    add_round_key(0, state, round_key);

    // There will be nr rounds.
    // The first nr-1 rounds are identical.
    // These nr-1 rounds are executed in the loop below.
    for round in 1..nr {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(round, state, round_key);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    sub_bytes(state);
    shift_rows(state);
    add_round_key(nr, state, round_key);
}

fn inv_cipher(nr: u8, state: &mut [u8], round_key: &[u8]) {
    // Add the First round key to the state before starting the rounds.
    add_round_key(nr, state, round_key);

    // There will be nr rounds.
    // The first nr-1 rounds are identical.
    // These nr-1 rounds are executed in the loop below.
    for round in (1..nr).rev() {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(round, state, round_key);
        inv_mix_columns(state);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(0, state, round_key);
}


pub fn aes_ecb_encrypt(ctx: &AES, buf: &mut [u8]) {
    // The next function call encrypts the PlainText with the Key using AES algorithm.
    cipher(ctx.nr(), buf, &ctx.round_key);
}

pub fn aes_ecb_decrypt(ctx: &AES, buf: &mut [u8]) {
    // The next function call decrypts the PlainText with the Key using AES algorithm.
    inv_cipher(ctx.nr(), buf, &ctx.round_key);
}

fn xor_with_iv(buf: &mut [u8], iv: &[u8]) {
    // The block in AES is always 128bit no matter the key size
    for i in 0..16 {
        buf[i] ^= iv[i];
    }
}

pub fn aes_cbc_encrypt_buffer(ctx: &mut AES, buf: &mut [u8]) {
    // uint8_t *Iv = ctx->Iv;
    let mut hist = [0u8; 16];
    hist.copy_from_slice(&ctx.iv);
    let mut iv: &mut [u8] = &mut hist;
    for chunk in buf.chunks_mut(16 as usize) {
        xor_with_iv(chunk, &iv);
        cipher(ctx.nr(), chunk, &ctx.round_key);
        iv = chunk;
        //printf("Step %d - %d", i/16, i);
    }
    /* store Iv in ctx for next call */
    ctx.iv.copy_from_slice(iv)
}

pub fn aes_cbc_decrypt_buffer(ctx: &mut AES, buf: &mut [u8]) {
    let mut next_iv = [0u8; 16];
    for chunk in buf.chunks_mut(16 as usize) {
        next_iv.copy_from_slice(chunk);
        inv_cipher(ctx.nr(), chunk, &ctx.round_key);
        xor_with_iv(chunk, &ctx.iv);
        ctx.iv.copy_from_slice(&next_iv);
    }
}


// Symmetrical operation: same function for encrypting as for decrypting.
// Note: Any IV/nonce should never be reused with the same key
pub fn aes_ctr_xcrypt_buffer(ctx: &mut AES, buf: &mut [u8]) {
    let mut bi = 16;
    let mut buffer = [0u8; 16];

    for i in 0..buf.len() {
        /* we need to regen xor complement in buffer */
        if bi == 16 {
            buffer.copy_from_slice(&ctx.iv);
            cipher(ctx.nr(), &mut buffer, &ctx.round_key);

            /* Increment Iv and handle overflow */
            for el in ctx.iv.iter_mut().rev() {
                if *el == 255 {
                    *el = 0;
                    continue;
                }
                *el += 1;
                break;
            }
            bi = 0;
        }

        buf[i] = buf[i] ^ buffer[bi as usize];
        bi += 1;
    }
}
