//! Password, passphrase and PIN generation.
//!
//! Randomness comes straight from the operating system (`getrandom`), and
//! characters are chosen with rejection sampling so that the distribution is
//! uniform — a plain `% len` would bias the first characters of the alphabet
//! and quietly shave bits off the entropy.

use crate::crypto::random_bytes;
use crate::error::{Error, Result};
use crate::wordlist;
use serde::{Deserialize, Serialize};

/// Default symbol set. Chosen to be accepted by nearly every website.
pub const DEFAULT_SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?";

/// Characters that are easy to confuse when read aloud or copied by hand.
const AMBIGUOUS: &str = "0O1lI|`'\";:,.";

/// How a password should be shaped.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PasswordPolicy {
    /// Total length of the generated password.
    pub length: usize,
    /// Include `a-z`.
    pub lowercase: bool,
    /// Include `A-Z`.
    pub uppercase: bool,
    /// Include `0-9`.
    pub digits: bool,
    /// Include punctuation.
    pub symbols: bool,
    /// Drop look-alike characters (`0`/`O`, `1`/`l`/`I`, …).
    pub exclude_ambiguous: bool,
    /// Overrides [`DEFAULT_SYMBOLS`] when non-empty.
    #[serde(default)]
    pub symbols_set: String,
    /// Guarantee at least one character from every selected class.
    #[serde(default = "yes")]
    pub require_each_class: bool,
}

fn yes() -> bool {
    true
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
            symbols_set: String::new(),
            require_each_class: true,
        }
    }
}

impl PasswordPolicy {
    /// A short, all-lowercase policy that satisfies picky legacy systems.
    pub fn alphanumeric(length: usize) -> Self {
        Self {
            length,
            symbols: false,
            ..Self::default()
        }
    }

    /// A four-digit PIN.
    pub fn pin() -> Self {
        Self {
            length: 4,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
            symbols_set: String::new(),
            require_each_class: false,
        }
    }

    /// The characters this policy may draw from, per class.
    fn classes(&self) -> Vec<String> {
        let mut out = Vec::new();
        let filter = |s: &str| -> String {
            if self.exclude_ambiguous {
                s.chars().filter(|c| !AMBIGUOUS.contains(*c)).collect()
            } else {
                s.to_string()
            }
        };
        if self.lowercase {
            out.push(filter("abcdefghijklmnopqrstuvwxyz"));
        }
        if self.uppercase {
            out.push(filter("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        }
        if self.digits {
            out.push(filter("0123456789"));
        }
        if self.symbols {
            let set = if self.symbols_set.is_empty() {
                DEFAULT_SYMBOLS
            } else {
                &self.symbols_set
            };
            out.push(filter(set));
        }
        out.retain(|c| !c.is_empty());
        out
    }

    /// The full alphabet, deduplicated.
    pub fn alphabet(&self) -> String {
        let mut chars: Vec<char> = self.classes().iter().flat_map(|c| c.chars()).collect();
        chars.sort_unstable();
        chars.dedup();
        chars.into_iter().collect()
    }

    /// Shannon entropy of one password drawn from this policy, in bits.
    pub fn entropy_bits(&self) -> f64 {
        let alphabet = self.alphabet().len();
        if alphabet <= 1 {
            return 0.0;
        }
        self.length as f64 * (alphabet as f64).log2()
    }

    /// Reject policies that cannot produce a password.
    pub fn validate(&self) -> Result<()> {
        let classes = self.classes();
        if classes.is_empty() {
            return Err(Error::ImpossiblePolicy(
                "no character set is enabled".into(),
            ));
        }
        if self.length == 0 {
            return Err(Error::ImpossiblePolicy("length must be at least 1".into()));
        }
        if self.length > 1024 {
            return Err(Error::ImpossiblePolicy(
                "length above 1024 is probably a mistake".into(),
            ));
        }
        if self.require_each_class && self.length < classes.len() {
            return Err(Error::ImpossiblePolicy(format!(
                "length {} cannot include one character from each of the {} enabled classes",
                self.length,
                classes.len()
            )));
        }
        Ok(())
    }

    /// One-line human summary, e.g. `20 chars · 128 bits`.
    pub fn summary(&self) -> String {
        format!(
            "{} chars · {:.0} bits",
            self.length,
            self.entropy_bits().round()
        )
    }
}

/// Uniformly random `u32` in `0..upper` via rejection sampling.
fn random_below(upper: u32) -> u32 {
    assert!(upper > 0, "upper bound must be positive");
    // Largest multiple of `upper` that fits in u32; values at or above it are
    // rejected so every residue is equally likely.
    let zone = u32::MAX - (u32::MAX % upper);
    loop {
        let candidate = u32::from_le_bytes(random_bytes::<4>());
        if candidate < zone {
            return candidate % upper;
        }
    }
}

/// Pick one character from a slice without bias.
fn pick<T: Copy>(items: &[T]) -> T {
    items[random_below(items.len() as u32) as usize]
}

/// Generate a password satisfying `policy`.
pub fn generate_password(policy: &PasswordPolicy) -> Result<String> {
    policy.validate()?;
    let classes = policy.classes();
    let alphabet: Vec<char> = policy.alphabet().chars().collect();

    let mut out: Vec<char> = Vec::with_capacity(policy.length);

    if policy.require_each_class {
        // Seed one character per class, then fill the rest, then shuffle so the
        // guaranteed characters do not always sit at the front.
        for class in &classes {
            let chars: Vec<char> = class.chars().collect();
            out.push(pick(&chars));
        }
    }
    while out.len() < policy.length {
        out.push(pick(&alphabet));
    }

    shuffle(&mut out);
    Ok(out.into_iter().collect())
}

/// Fisher–Yates shuffle with OS randomness.
fn shuffle(chars: &mut [char]) {
    for i in (1..chars.len()).rev() {
        let j = random_below(i as u32 + 1) as usize;
        chars.swap(i, j);
    }
}

/// Generate a diceware-style passphrase from the EFF long word list.
///
/// * `words` — how many words (six ≈ 77 bits).
/// * `separator` — inserted between words.
/// * `capitalize` — capitalise each word.
/// * `append_number` — append a random two-digit number.
pub fn generate_passphrase(
    words: usize,
    separator: &str,
    capitalize: bool,
    append_number: bool,
) -> Result<String> {
    let count = words.clamp(2, 24);
    let list = wordlist::words();
    if list.is_empty() {
        return Err(Error::other("the bundled word list is empty"));
    }
    let mut chosen: Vec<String> = (0..count)
        .map(|_| {
            let word = list[random_below(list.len() as u32) as usize];
            if capitalize {
                let mut c = word.chars();
                match c.next() {
                    Some(first) => format!("{}{}", first.to_ascii_uppercase(), c.as_str()),
                    None => String::new(),
                }
            } else {
                word.to_string()
            }
        })
        .collect();
    if append_number {
        let n = random_below(100);
        let last = chosen.len() - 1;
        chosen[last] = format!("{}{:02}", chosen[last], n);
    }
    Ok(chosen.join(separator))
}

/// Entropy of a passphrase, in bits.
pub fn passphrase_entropy_bits(words: usize, append_number: bool) -> f64 {
    let per_word = (wordlist::words().len().max(1) as f64).log2();
    let extra = if append_number { (100f64).log2() } else { 0.0 };
    (words.clamp(2, 24) as f64) * per_word + extra
}

/// Generate a numeric PIN of `length` digits.
pub fn generate_pin(length: usize) -> Result<String> {
    let mut policy = PasswordPolicy::pin();
    policy.length = length.clamp(3, 32);
    policy.validate()?;
    let digits: Vec<char> = "0123456789".chars().collect();
    Ok((0..policy.length).map(|_| pick(&digits)).collect())
}

/// Rate the strength of an existing password, as a two-line summary.
pub fn describe_strength(password: &str) -> String {
    let s = crate::strength::evaluate(password, &[]);
    format!("{} · {}", s.label, s.crack_time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_passwords_respect_the_policy() {
        let policy = PasswordPolicy {
            length: 24,
            ..Default::default()
        };
        for _ in 0..64 {
            let pw = generate_password(&policy).unwrap();
            assert_eq!(pw.chars().count(), 24);
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()));
            assert!(pw.chars().any(|c| !c.is_ascii_alphanumeric()));
            assert!(!pw.contains(['0', 'O', '1', 'l', 'I']));
        }
    }

    #[test]
    fn generated_passwords_are_unique() {
        let policy = PasswordPolicy::default();
        let set: HashSet<String> = (0..500)
            .map(|_| generate_password(&policy).unwrap())
            .collect();
        assert_eq!(set.len(), 500, "generator should not repeat itself");
    }

    #[test]
    fn impossible_policies_are_rejected() {
        let empty = PasswordPolicy {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(empty.validate().is_err());

        let too_short = PasswordPolicy {
            length: 2,
            ..Default::default()
        };
        assert!(too_short.validate().is_err());
    }

    #[test]
    fn passphrases_have_the_expected_shape() {
        let phrase = generate_passphrase(6, "-", true, true).unwrap();
        let parts: Vec<&str> = phrase.split('-').collect();
        assert_eq!(parts.len(), 6);
        assert!(parts[0].chars().next().unwrap().is_ascii_uppercase());
        assert!(passphrase_entropy_bits(6, true) > 77.0);
    }

    #[test]
    fn pins_are_numeric() {
        let pin = generate_pin(6).unwrap();
        assert_eq!(pin.len(), 6);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn entropy_grows_with_length() {
        let a = PasswordPolicy {
            length: 10,
            ..Default::default()
        };
        let b = PasswordPolicy {
            length: 20,
            ..Default::default()
        };
        assert!(b.entropy_bits() > a.entropy_bits());
        assert!(a.entropy_bits() > 60.0);
    }
}
