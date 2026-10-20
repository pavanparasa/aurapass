//! The bundled diceware word list.
//!
//! Data file: `data/eff_large_wordlist.txt`, the *EFF large word list for
//! passphrases* (7 776 words, ≈12.9 bits per word). It is published by the
//! Electronic Frontier Foundation under CC BY 3.0
//! (<https://www.eff.org/dice>), and fetched from GitHub-hosted copies. The file
//! format is `dice-number<TAB>word`, e.g. `11111<TAB>abacus`; the dice numbers
//! are not needed here, so only the second column is kept.

use std::sync::OnceLock;

const RAW: &str = include_str!("../data/eff_large_wordlist.txt");

static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();

/// Every word in the list, in file order. Loaded once, then cached.
pub fn words() -> &'static [&'static str] {
    WORDS.get_or_init(|| {
        RAW.lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                let word = line.rsplit('\t').next()?.trim();
                if word.is_empty() || word.contains(char::is_whitespace) {
                    None
                } else {
                    Some(word)
                }
            })
            .collect()
    })
}

/// Number of available words (7 776 for the EFF list).
pub fn count() -> usize {
    words().len()
}

/// Look up a word by position, if it exists.
pub fn word_at(index: usize) -> Option<&'static str> {
    words().get(index).copied()
}

/// Entropy contributed by a single word, in bits.
pub fn bits_per_word() -> f64 {
    (count().max(1) as f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_loaded_and_clean() {
        assert_eq!(count(), 7776, "the EFF long list has 7776 words");
        assert_eq!(words()[0], "abacus");
        assert!(words().iter().all(|w| !w.is_empty()));
        assert!((bits_per_word() - 12.9).abs() < 0.1);
    }

    #[test]
    fn no_duplicate_words() {
        let mut sorted = words().to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "word list contains duplicates");
    }
}
