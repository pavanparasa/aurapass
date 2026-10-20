//! Password-strength scoring.
//!
//! A thin wrapper over [`zxcvbn`] (the Dropbox estimator), so the rest of the
//! code base never has to care about its API shape. zxcvbn models real-world
//! cracking: dictionary words, keyboard walks, repeats, dates and l33t speak.

use std::sync::OnceLock;

/// Result of scoring one password.
#[derive(Debug, Clone)]
pub struct Strength {
    /// zxcvbn score, `0` (terrible) to `4` (excellent).
    pub score: u8,
    /// Estimated number of guesses needed.
    pub guesses: f64,
    /// `log10` of [`Strength::guesses`].
    pub log10_guesses: f64,
    /// Short verdict, e.g. "Strong".
    pub label: &'static str,
    /// Human crack-time estimate.
    pub crack_time: &'static str,
    /// zxcvbn's warning, when it has one.
    pub warning: Option<String>,
    /// Concrete suggestions ("Add another word or two").
    pub suggestions: Vec<String>,
}

impl Strength {
    /// Fraction in `0.0..=1.0`, for progress bars.
    pub fn fraction(&self) -> f32 {
        self.score as f32 / 4.0
    }

    /// Colour hint as `(r, g, b)`, from red through amber to green.
    pub fn color(&self) -> (u8, u8, u8) {
        match self.score {
            0 => (0xd6, 0x4b, 0x3f),
            1 => (0xe0, 0x84, 0x3c),
            2 => (0xd9, 0xb8, 0x36),
            3 => (0x8a, 0xbc, 0x3c),
            _ => (0x3f, 0xa8, 0x5c),
        }
    }

    /// Entropy in bits, inferred from the guess count.
    pub fn bits(&self) -> f64 {
        self.log10_guesses * std::f64::consts::LOG2_10
    }
}

/// A cheap 0–4 estimate for long lists.
///
/// This is deliberately not [`evaluate`]: zxcvbn is far too expensive to run
/// over every item while scrolling a 1,600-entry vault. It only looks at
/// length and character classes, so it is a hint for the list's warning badge;
/// the detail pane and editor still show the real zxcvbn score.
pub fn quick_score(password: &str) -> u8 {
    let len = password.chars().count();
    if len == 0 {
        return 0;
    }
    let lower = password.chars().any(|c| c.is_ascii_lowercase());
    let upper = password.chars().any(|c| c.is_ascii_uppercase());
    let digit = password.chars().any(|c| c.is_ascii_digit());
    let symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());
    let classes = [lower, upper, digit, symbol]
        .into_iter()
        .filter(|present| *present)
        .count();

    match (len, classes) {
        (0, _) => 0,
        (0..=7, _) => 0,
        (8..=9, 0..=1) => 0,
        (8..=9, _) => 2,
        (10..=11, 0..=1) => 1,
        (10..=11, _) => 2,
        (12..=15, 0..=1) => 2,
        (12..=15, _) => 3,
        (16.., 0..=1) => 2,
        (16.., _) => 4,
    }
}

/// Score a password. `user_inputs` are extra dictionary words that should count
/// as weak (the item title, the user name, the vault name…).
pub fn evaluate(password: &str, user_inputs: &[&str]) -> Strength {
    if password.is_empty() {
        return Strength {
            score: 0,
            guesses: 0.0,
            log10_guesses: 0.0,
            label: "Empty",
            crack_time: "instantly",
            warning: Some("This entry has no password.".into()),
            suggestions: vec!["Use the generator to create one.".into()],
        };
    }

    static INPUTS: OnceLock<()> = OnceLock::new();
    let _ = INPUTS.get_or_init(|| ());

    let entropy = zxcvbn::zxcvbn(password, user_inputs);
    let score = u8::from(entropy.score()).min(4);
    let guesses = entropy.guesses() as f64;
    let log10 = entropy.guesses_log10();
    let feedback = entropy.feedback();

    Strength {
        score,
        guesses,
        log10_guesses: log10,
        label: label_for(score),
        crack_time: crack_time_for(guesses),
        warning: feedback
            .as_ref()
            .and_then(|f| f.warning())
            .map(|w| w.to_string()),
        suggestions: feedback
            .as_ref()
            .map(|f| f.suggestions().iter().map(|s| s.to_string()).collect())
            .unwrap_or_default(),
    }
}

fn label_for(score: u8) -> &'static str {
    match score {
        0 => "Very weak",
        1 => "Weak",
        2 => "Fair",
        3 => "Strong",
        _ => "Excellent",
    }
}

/// Assume an attacker who can try 10^10 guesses per second — roughly a rack of
/// GPUs attacking a fast hash. It is deliberately pessimistic and only meant as
/// a rough guide.
fn crack_time_for(guesses: f64) -> &'static str {
    const PER_SECOND: f64 = 1e10;
    if guesses <= 0.0 {
        return "instantly";
    }
    let seconds = guesses / PER_SECOND;
    let minutes = seconds / 60.0;
    let hours = minutes / 60.0;
    let days = hours / 24.0;
    let years = days / 365.25;
    if seconds < 1.0 {
        "instantly"
    } else if minutes < 1.0 {
        "seconds"
    } else if hours < 1.0 {
        "minutes"
    } else if days < 1.0 {
        "hours"
    } else if days < 31.0 {
        "days"
    } else if years < 1.0 {
        "months"
    } else if years < 100.0 {
        "years"
    } else if years < 1e6 {
        "centuries"
    } else {
        "beyond guessing"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obvious_passwords_are_weak() {
        assert!(evaluate("password", &[]).score <= 1);
        assert!(evaluate("123456", &[]).score <= 1);
        assert_eq!(evaluate("", &[]).label, "Empty");
    }

    #[test]
    fn long_random_passwords_score_well() {
        let s = evaluate("vT7#qLm2!xR9@wZp4^bN", &[]);
        assert!(s.score >= 3, "expected strong, got {s:?}");
        assert!(s.bits() > 60.0);
    }

    #[test]
    fn quick_score_tracks_length_and_classes() {
        assert_eq!(quick_score(""), 0);
        assert_eq!(quick_score("abc"), 0);
        assert!(quick_score("vT7#qLm2!xR9@wZp4^bN") >= 3);
        assert!(quick_score("correct horse battery staple") >= 2);
    }

    #[test]
    fn user_inputs_weaken_a_match() {
        let with_context = evaluate("acme-corp-2026!", &["acme"]);
        let without = evaluate("acme-corp-2026!", &[]);
        assert!(with_context.log10_guesses <= without.log10_guesses);
    }
}
