//! A minimal implementation of SHA1 for rust.
//!
//! This implementation supports no_std which is the default mode.  The
//! following features are available and can be optionally enabled:
//!
//! * ``serde``: when enabled the `Digest` type can be serialized.
//! * ``std``: when enabled errors from this library implement `std::error::Error`
//!   and the `hexdigest` shortcut becomes available.
//!
//! Simple Example:
//!
//! ```rust
//! extern crate sha1;
//! # fn main() {
//!
//! let mut m = sha1::Sha1::new();
//! m.update(b"Hello World!");
//! assert_eq!(m.digest().to_string(),
//!            "2ef7bde608ce5404e97d5f042f95f89f1c232871");
//! # }
//! ```
//!
//! The sha1 object can be updated multiple times.  If you only need to use
//! it once you can also use shortcuts:
//!
//! ```
//! extern crate sha1;
//! # fn main() {
//! assert_eq!(sha1::Sha1::from("Hello World!").hexdigest(),
//!            "2ef7bde608ce5404e97d5f042f95f89f1c232871");
//! # }
//! ```

#![deny(missing_docs)]

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(feature = "std")]
extern crate std;

use core::cmp;
use core::fmt;
use core::hash;
use core::mem;
use core::str;

use crate::simd::*;

/// The length of a SHA1 digest in bytes
pub const DIGEST_LENGTH: usize = 20;

/// Represents a Sha1 hash object in memory.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct Sha1 {
    state: Sha1State,
    blocks: Blocks,
    len: u64,
}

struct Blocks {
    len: u32,
    block: [u8; 64],
}

#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Default)]
struct Sha1State {
    state: [u32; 5],
}

/// Digest generated from a `Sha1` instance.
///
/// A digest can be formatted to view the digest as a hex string, or the bytes
/// can be extracted for later processing.
///
/// To retrieve a hex string result call `to_string` on it (requires that std
/// is available).
///
/// If the `serde` feature is enabled a digest can also be serialized and
/// deserialized.  Likewise a digest can be parsed from a hex string.
#[derive(PartialOrd, Ord, PartialEq, Eq, Hash, Clone, Copy, Default)]
pub struct Digest {
    data: Sha1State,
}

const DEFAULT_STATE: Sha1State = Sha1State {
    state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
};

#[inline(always)]
fn as_block(input: &[u8]) -> &[u8; 64] {
    unsafe {
        assert!(input.len() == 64);
        let arr: &[u8; 64] = mem::transmute(input.as_ptr());
        arr
    }
}

impl Default for Sha1 {
    fn default() -> Sha1 {
        Sha1::new()
    }
}

impl Sha1 {
    /// Creates an fresh sha1 hash object.
    ///
    /// This is equivalent to creating a hash with `Default::default`.
    pub fn new() -> Sha1 {
        Sha1 {
            state: DEFAULT_STATE,
            len: 0,
            blocks: Blocks {
                len: 0,
                block: [0; 64],
            },
        }
    }

    /// Jack's interface for doing length extensions
    pub fn from_state_bytes(bytes: &[u8; 20], orig_len: u64) -> Sha1 {
        let mut padded_len = orig_len + 9;
        if padded_len % 64 != 0 {
            padded_len += 64 - (padded_len % 64);
        }
        assert_eq!(padded_len % 64, 0);
        let mut state = [0; 5];
        for (word, chunk) in state.iter_mut().zip(bytes.chunks_exact(4)) {
            let mut array = [0; 4];
            array.copy_from_slice(chunk);
            *word = u32::from_be_bytes(array);
        }
        Sha1 {
            state: Sha1State { state },
            len: padded_len,
            blocks: Blocks {
                len: 0,
                block: [0; 64],
            },
        }
    }

    /// Shortcut to create a sha1 from some bytes.
    ///
    /// This also lets you create a hash from a utf-8 string.  This is equivalent
    /// to making a new Sha1 object and calling `update` on it once.
    pub fn from<D: AsRef<[u8]>>(data: D) -> Sha1 {
        let mut rv = Sha1::new();
        rv.update(data.as_ref());
        rv
    }

    /// Resets the hash object to it's initial state.
    pub fn reset(&mut self) {
        self.state = DEFAULT_STATE;
        self.len = 0;
        self.blocks.len = 0;
    }

    /// Update hash with input data.
    pub fn update(&mut self, data: &[u8]) {
        let len = &mut self.len;
        let state = &mut self.state;
        self.blocks.input(data, |block| {
            *len += block.len() as u64;
            state.process(block);
        })
    }

    /// Retrieve digest result.
    pub fn digest(&self) -> Digest {
        let mut state = self.state;
        let bits = (self.len + (self.blocks.len as u64)) * 8;
        let extra = [
            (bits >> 56) as u8,
            (bits >> 48) as u8,
            (bits >> 40) as u8,
            (bits >> 32) as u8,
            (bits >> 24) as u8,
            (bits >> 16) as u8,
            (bits >> 8) as u8,
            (bits >> 0) as u8,
        ];
        let mut last = [0; 128];
        let blocklen = self.blocks.len as usize;
        last[..blocklen].clone_from_slice(&self.blocks.block[..blocklen]);
        last[blocklen] = 0x80;

        if blocklen < 56 {
            last[56..64].clone_from_slice(&extra);
            state.process(as_block(&last[0..64]));
        } else {
            last[120..128].clone_from_slice(&extra);
            state.process(as_block(&last[0..64]));
            state.process(as_block(&last[64..128]));
        }

        Digest { data: state }
    }

    /// Retrieve the digest result as hex string directly.
    ///
    /// (The function is only available if the `std` feature is enabled)
    #[cfg(feature = "std")]
    pub fn hexdigest(&self) -> std::string::String {
        use std::string::ToString;
        self.digest().to_string()
    }
}

impl Digest {
    /// Returns the 160 bit (20 byte) digest as a byte array.
    pub fn bytes(&self) -> [u8; DIGEST_LENGTH] {
        [
            (self.data.state[0] >> 24) as u8,
            (self.data.state[0] >> 16) as u8,
            (self.data.state[0] >> 8) as u8,
            (self.data.state[0] >> 0) as u8,
            (self.data.state[1] >> 24) as u8,
            (self.data.state[1] >> 16) as u8,
            (self.data.state[1] >> 8) as u8,
            (self.data.state[1] >> 0) as u8,
            (self.data.state[2] >> 24) as u8,
            (self.data.state[2] >> 16) as u8,
            (self.data.state[2] >> 8) as u8,
            (self.data.state[2] >> 0) as u8,
            (self.data.state[3] >> 24) as u8,
            (self.data.state[3] >> 16) as u8,
            (self.data.state[3] >> 8) as u8,
            (self.data.state[3] >> 0) as u8,
            (self.data.state[4] >> 24) as u8,
            (self.data.state[4] >> 16) as u8,
            (self.data.state[4] >> 8) as u8,
            (self.data.state[4] >> 0) as u8,
        ]
    }
}

impl Blocks {
    fn input<F>(&mut self, mut input: &[u8], mut f: F)
    where
        F: FnMut(&[u8; 64]),
    {
        if self.len > 0 {
            let len = self.len as usize;
            let amt = cmp::min(input.len(), self.block.len() - len);
            self.block[len..len + amt].clone_from_slice(&input[..amt]);
            if len + amt == self.block.len() {
                f(&self.block);
                self.len = 0;
                input = &input[amt..];
            } else {
                self.len += amt as u32;
                return;
            }
        }
        assert_eq!(self.len, 0);
        for chunk in input.chunks(64) {
            if chunk.len() == 64 {
                f(as_block(chunk))
            } else {
                self.block[..chunk.len()].clone_from_slice(chunk);
                self.len = chunk.len() as u32;
            }
        }
    }
}

// Round key constants
const K0: u32 = 0x5A827999u32;
const K1: u32 = 0x6ED9EBA1u32;
const K2: u32 = 0x8F1BBCDCu32;
const K3: u32 = 0xCA62C1D6u32;

/// Not an intrinsic, but gets the first element of a vector.
#[inline]
fn sha1_first(w0: u32x4) -> u32 {
    w0.0
}

/// Not an intrinsic, but adds a word to the first element of a vector.
#[inline]
fn sha1_first_add(e: u32, w0: u32x4) -> u32x4 {
    let u32x4(a, b, c, d) = w0;
    u32x4(e.wrapping_add(a), b, c, d)
}

/// Emulates `llvm.x86.sha1msg1` intrinsic.
fn sha1msg1(a: u32x4, b: u32x4) -> u32x4 {
    let u32x4(_, _, w2, w3) = a;
    let u32x4(w4, w5, _, _) = b;
    a ^ u32x4(w2, w3, w4, w5)
}

/// Emulates `llvm.x86.sha1msg2` intrinsic.
fn sha1msg2(a: u32x4, b: u32x4) -> u32x4 {
    let u32x4(x0, x1, x2, x3) = a;
    let u32x4(_, w13, w14, w15) = b;

    let w16 = (x0 ^ w13).rotate_left(1);
    let w17 = (x1 ^ w14).rotate_left(1);
    let w18 = (x2 ^ w15).rotate_left(1);
    let w19 = (x3 ^ w16).rotate_left(1);

    u32x4(w16, w17, w18, w19)
}

/// Emulates `llvm.x86.sha1nexte` intrinsic.
#[inline]
fn sha1_first_half(abcd: u32x4, msg: u32x4) -> u32x4 {
    sha1_first_add(sha1_first(abcd).rotate_left(30), msg)
}

/// Emulates `llvm.x86.sha1rnds4` intrinsic.
/// Performs 4 rounds of the message block digest.
fn sha1_digest_round_x4(abcd: u32x4, work: u32x4, i: i8) -> u32x4 {
    const K0V: u32x4 = u32x4(K0, K0, K0, K0);
    const K1V: u32x4 = u32x4(K1, K1, K1, K1);
    const K2V: u32x4 = u32x4(K2, K2, K2, K2);
    const K3V: u32x4 = u32x4(K3, K3, K3, K3);

    match i {
        0 => sha1rnds4c(abcd, work + K0V),
        1 => sha1rnds4p(abcd, work + K1V),
        2 => sha1rnds4m(abcd, work + K2V),
        3 => sha1rnds4p(abcd, work + K3V),
        _ => panic!("unknown icosaround index"),
    }
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4c(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_202 {
        ($a:expr, $b:expr, $c:expr) => {
            ($c ^ ($a & ($b ^ $c)))
        };
    } // Choose, MD5F, SHA1C

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_202!(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_202!(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_202!(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_202!(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4p(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_150 {
        ($a:expr, $b:expr, $c:expr) => {
            ($a ^ $b ^ $c)
        };
    } // Parity, XOR, MD5H, SHA1P

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_150!(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_150!(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_150!(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_150!(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4m(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_232 {
        ($a:expr, $b:expr, $c:expr) => {
            ($a & $b) ^ ($a & $c) ^ ($b & $c)
        };
    } // Majority, SHA1M

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_232!(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_232!(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_232!(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_232!(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

impl Sha1State {
    fn process(&mut self, block: &[u8; 64]) {
        let mut words = [0u32; 16];
        for i in 0..16 {
            let off = i * 4;
            words[i] = (block[off + 3] as u32)
                | ((block[off + 2] as u32) << 8)
                | ((block[off + 1] as u32) << 16)
                | ((block[off] as u32) << 24);
        }
        macro_rules! schedule {
            ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
                sha1msg2(sha1msg1($v0, $v1) ^ $v2, $v3)
            };
        }

        macro_rules! rounds4 {
            ($h0:ident, $h1:ident, $wk:expr, $i:expr) => {
                sha1_digest_round_x4($h0, sha1_first_half($h1, $wk), $i)
            };
        }

        // Rounds 0..20
        let mut h0 = u32x4(self.state[0], self.state[1], self.state[2], self.state[3]);
        let mut w0 = u32x4(words[0], words[1], words[2], words[3]);
        let mut h1 = sha1_digest_round_x4(h0, sha1_first_add(self.state[4], w0), 0);
        let mut w1 = u32x4(words[4], words[5], words[6], words[7]);
        h0 = rounds4!(h1, h0, w1, 0);
        let mut w2 = u32x4(words[8], words[9], words[10], words[11]);
        h1 = rounds4!(h0, h1, w2, 0);
        let mut w3 = u32x4(words[12], words[13], words[14], words[15]);
        h0 = rounds4!(h1, h0, w3, 0);
        let mut w4 = schedule!(w0, w1, w2, w3);
        h1 = rounds4!(h0, h1, w4, 0);

        // Rounds 20..40
        w0 = schedule!(w1, w2, w3, w4);
        h0 = rounds4!(h1, h0, w0, 1);
        w1 = schedule!(w2, w3, w4, w0);
        h1 = rounds4!(h0, h1, w1, 1);
        w2 = schedule!(w3, w4, w0, w1);
        h0 = rounds4!(h1, h0, w2, 1);
        w3 = schedule!(w4, w0, w1, w2);
        h1 = rounds4!(h0, h1, w3, 1);
        w4 = schedule!(w0, w1, w2, w3);
        h0 = rounds4!(h1, h0, w4, 1);

        // Rounds 40..60
        w0 = schedule!(w1, w2, w3, w4);
        h1 = rounds4!(h0, h1, w0, 2);
        w1 = schedule!(w2, w3, w4, w0);
        h0 = rounds4!(h1, h0, w1, 2);
        w2 = schedule!(w3, w4, w0, w1);
        h1 = rounds4!(h0, h1, w2, 2);
        w3 = schedule!(w4, w0, w1, w2);
        h0 = rounds4!(h1, h0, w3, 2);
        w4 = schedule!(w0, w1, w2, w3);
        h1 = rounds4!(h0, h1, w4, 2);

        // Rounds 60..80
        w0 = schedule!(w1, w2, w3, w4);
        h0 = rounds4!(h1, h0, w0, 3);
        w1 = schedule!(w2, w3, w4, w0);
        h1 = rounds4!(h0, h1, w1, 3);
        w2 = schedule!(w3, w4, w0, w1);
        h0 = rounds4!(h1, h0, w2, 3);
        w3 = schedule!(w4, w0, w1, w2);
        h1 = rounds4!(h0, h1, w3, 3);
        w4 = schedule!(w0, w1, w2, w3);
        h0 = rounds4!(h1, h0, w4, 3);

        let e = sha1_first(h1).rotate_left(30);
        let u32x4(a, b, c, d) = h0;

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

impl PartialEq for Blocks {
    fn eq(&self, other: &Blocks) -> bool {
        (self.len, &self.block[..]).eq(&(other.len, &other.block[..]))
    }
}

impl Ord for Blocks {
    fn cmp(&self, other: &Blocks) -> cmp::Ordering {
        (self.len, &self.block[..]).cmp(&(other.len, &other.block[..]))
    }
}

impl PartialOrd for Blocks {
    fn partial_cmp(&self, other: &Blocks) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for Blocks {}

impl hash::Hash for Blocks {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.len.hash(state);
        self.block.hash(state);
    }
}

impl Clone for Blocks {
    fn clone(&self) -> Blocks {
        Blocks { ..*self }
    }
}

/// Indicates that a digest couldn't be parsed.
#[derive(Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct DigestParseError(());

impl fmt::Display for DigestParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "not a valid sha1 hash")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DigestParseError {
    fn description(&self) -> &str {
        "not a valid sha1 hash"
    }
}

impl str::FromStr for Digest {
    type Err = DigestParseError;

    fn from_str(s: &str) -> Result<Digest, DigestParseError> {
        if s.len() != 40 {
            return Err(DigestParseError(()));
        }
        let mut rv: Digest = Default::default();
        for idx in 0..5 {
            rv.data.state[idx] = u32::from_str_radix(&s[idx * 8..idx * 8 + 8], 16)
                .map_err(|_| DigestParseError(()))?;
        }
        Ok(rv)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in self.data.state.iter() {
            write!(f, "{:08x}", i)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Digest {{ \"{}\" }}", self)
    }
}

#[cfg(feature = "serde")]
impl serde::ser::Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        fn to_hex(num: u8) -> u8 {
            b"0123456789abcdef"[num as usize]
        }

        let mut hex_str = [0u8; 40];
        let mut c = 0;
        for state in self.data.state.iter() {
            for off in 0..4 {
                let byte = (state >> (8 * (3 - off))) as u8;
                hex_str[c] = to_hex(byte >> 4);
                hex_str[c + 1] = to_hex(byte & 0xf);
                c += 2;
            }
        }
        serializer.serialize_str(unsafe { str::from_utf8_unchecked(&hex_str[..]) })
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::de::Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct V;

        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Digest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("SHA-1 hash")
            }

            fn visit_str<E>(self, value: &str) -> Result<Digest, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(|_| {
                    serde::de::Error::invalid_value(serde::de::Unexpected::Str(value), &self)
                })
            }
        }

        deserializer.deserialize_str(V)
    }
}
