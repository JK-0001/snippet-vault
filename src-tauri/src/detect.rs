//! Heuristics for "this copied text is probably a secret". Used by the
//! clipboard recorder to mask or skip such clips. False positives only make
//! a clip masked, so the rules lean towards catching things.

use regex::RegexSet;
use std::sync::OnceLock;

fn patterns() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| {
        RegexSet::new([
            r"AKIA[0-9A-Z]{16}",                                           // AWS access key
            r"(?i)aws(.{0,20})?(secret|private).{0,20}[A-Za-z0-9/+=]{40}", // AWS secret
            r"sk-[A-Za-z0-9_-]{20,}", // OpenAI / Anthropic / Stripe
            r"(?:rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}", // Stripe
            r"gh[pousr]_[A-Za-z0-9]{30,}", // GitHub tokens
            r"github_pat_[A-Za-z0-9_]{40,}",
            r"xox[abprs]-[A-Za-z0-9-]{10,}", // Slack
            r"AIza[0-9A-Za-z_-]{35}",        // Google API key
            r"ya29\.[0-9A-Za-z_-]+",         // Google OAuth
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", // JWT
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            r"(?i)(api[_-]?key|secret|token|passw(or)?d)\s*[:=]\s*\S{8,}",
            r"(?i)^Bearer\s+[A-Za-z0-9._~+/-]{20,}=*$",
            r"[0-9a-f]{32}",       // hex secrets / md5-like
            r"[A-Za-z0-9_-]{40,}", // long opaque tokens
        ])
        .expect("secret patterns compile")
    })
}

/// Shannon entropy in bits per character.
fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let mut n = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n as f64;
            -p * p.log2()
        })
        .sum()
}

/// True if `text` looks like a password, key or token rather than prose.
pub fn looks_secret(text: &str) -> bool {
    let t = text.trim();
    if t.is_empty() || t.chars().count() > 4096 {
        return false;
    }
    if patterns().is_match(t) {
        return true;
    }
    // A single dense token, password-like: no spaces, 12..=128 chars, mixed
    // classes and high entropy.
    if !t.contains(char::is_whitespace) {
        let len = t.chars().count();
        let has_digit = t.chars().any(|c| c.is_ascii_digit());
        let has_alpha = t.chars().any(|c| c.is_alphabetic());
        let has_upper = t.chars().any(|c| c.is_uppercase());
        let has_symbol = t.chars().any(|c| !c.is_alphanumeric());
        let classes = [has_digit, has_alpha, has_upper, has_symbol]
            .iter()
            .filter(|&&b| b)
            .count();
        let looks_url = t.starts_with("http://") || t.starts_with("https://") || t.contains("://");
        if !looks_url && (12..=128).contains(&len) && classes >= 3 && entropy(t) >= 3.3 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_common_keys() {
        assert!(looks_secret(
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"
        ));
        assert!(looks_secret("AKIAIOSFODNN7EXAMPLE"));
        assert!(looks_secret("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456"));
        assert!(looks_secret("password = hunter2hunter2"));
        assert!(looks_secret("Tr0ub4dor&3xyz!"));
        assert!(looks_secret("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."));
    }

    #[test]
    fn leaves_prose_alone() {
        assert!(!looks_secret(
            "Hi team, please find the report attached. Thanks!"
        ));
        assert!(!looks_secret(
            "https://example.com/some/long/path?with=query"
        ));
        assert!(!looks_secret("meeting at 10am"));
        assert!(!looks_secret("Jatin"));
        assert!(!looks_secret(""));
    }
}
