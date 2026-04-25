use rand::seq::IteratorRandom as _;
use zeroize::Zeroize as _;

use crate::locked;

const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const NUMBERS: &[u8] = b"0123456789";
const LETTERS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NONCONFUSABLES: &[u8] = b"34678abcdefhjkmnpqrtuwxy";

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Type {
    AllChars,
    NoSymbols,
    Numbers,
    NonConfusables,
    Diceware,
}

/// Generate a password into a `locked::Password`.
///
/// The result is mlocked + zeroized on drop. Downstream code that clones
/// the value into a plain `String` (e.g. the rmpv-encoded `Action::Encrypt`
/// payload sent over the agent socket) reintroduces heap exposure; this
/// function only eliminates it in the immediate caller's scope.
pub fn pwgen(ty: Type, len: usize) -> locked::Password {
    let mut rng = rand::rng();

    let alphabet = match ty {
        Type::AllChars => {
            let mut v = vec![];
            v.extend(SYMBOLS.iter().copied());
            v.extend(NUMBERS.iter().copied());
            v.extend(LETTERS.iter().copied());
            v
        }
        Type::NoSymbols => {
            let mut v = vec![];
            v.extend(NUMBERS.iter().copied());
            v.extend(LETTERS.iter().copied());
            v
        }
        Type::Numbers => {
            let mut v = vec![];
            v.extend(NUMBERS.iter().copied());
            v
        }
        Type::NonConfusables => {
            let mut v = vec![];
            v.extend(NONCONFUSABLES.iter().copied());
            v
        }
        Type::Diceware => {
            return diceware(&mut rng, len);
        }
    };

    let mut buf = locked::Vec::new();
    buf.extend(
        std::iter::repeat_with(|| *alphabet.iter().choose(&mut rng).unwrap())
            .take(len),
    );
    locked::Password::new(buf)
}

fn diceware(rng: &mut impl rand::RngCore, len: usize) -> locked::Password {
    let mut words = vec![];
    for _ in 0..len {
        // unwrap is safe because choose only returns None for an empty slice
        words.push(*crate::wordlist::EFF_LONG.iter().choose(rng).unwrap());
    }
    let mut joined = words.join(" ");
    let mut buf = locked::Vec::new();
    buf.extend(joined.as_bytes().iter().copied());
    // The intermediate `String` held the full passphrase in plain heap;
    // scrub before drop.
    joined.zeroize();
    locked::Password::new(buf)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pwgen() {
        let pw = pwgen(Type::AllChars, 50);
        assert_eq!(pw.password().len(), 50);
        // technically this could fail, but the chances are incredibly low
        // (around 0.000009%)
        assert_duplicates(pw.password());

        let pw = pwgen(Type::AllChars, 100);
        assert_eq!(pw.password().len(), 100);
        assert_duplicates(pw.password());

        let pw = pwgen(Type::NoSymbols, 100);
        assert_eq!(pw.password().len(), 100);
        assert_duplicates(pw.password());

        let pw = pwgen(Type::Numbers, 100);
        assert_eq!(pw.password().len(), 100);
        assert_duplicates(pw.password());

        let pw = pwgen(Type::NonConfusables, 100);
        assert_eq!(pw.password().len(), 100);
        assert_duplicates(pw.password());
    }

    #[track_caller]
    fn assert_duplicates(bytes: &[u8]) {
        let s = std::str::from_utf8(bytes).unwrap();
        let mut set = std::collections::HashSet::new();
        for c in s.chars() {
            set.insert(c);
        }
        assert!(set.len() < s.len());
    }
}
