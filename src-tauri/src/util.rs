//! Small shared helpers. Currently just path / username redaction so
//! findings and saved reports don't leak the local user's real name.

/// Rewrite any `<drive>:\Users\<name>\…`, `/Users/<name>/…`, or
/// `/home/<name>/…` segment in `input` so the username is replaced with
/// `<user>`. Idempotent — running it twice on the same string yields the
/// same output.
///
/// This is intentionally conservative: it only redacts the one path
/// segment that follows the canonical users-directory marker. Arbitrary
/// other personal data inside a finding (machine name, org, hostname) is
/// out of scope — those need per-site handling if they ever appear.
pub fn redact_user_paths(input: &str) -> String {
    let mut out = input.to_string();
    for (marker, sep) in [("\\Users\\", '\\'), ("/Users/", '/'), ("/home/", '/')] {
        out = redact_after_marker(&out, marker, sep);
    }
    out
}

/// Apply the redaction rule for a single marker/separator pair. The marker
/// is matched literally (case-sensitive); after the marker we skip bytes
/// up to the next separator (or end-of-string) and replace that run with
/// `<user>`. Handles repeated occurrences.
fn redact_after_marker(input: &str, marker: &str, sep: char) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;
    while let Some(rel) = input[cursor..].find(marker) {
        let hit = cursor + rel;
        let after = hit + marker.len();
        out.push_str(&input[cursor..after]);
        // Already-redacted segment ("<user>") shouldn't be re-wrapped.
        if input[after..].starts_with("<user>") {
            cursor = after;
            continue;
        }
        match input[after..].find(sep) {
            Some(end_rel) => {
                // Non-empty user segment only; an empty segment (marker
                // immediately followed by sep) means the path was already
                // `\Users\\something` — leave it alone.
                if end_rel == 0 {
                    cursor = after;
                    continue;
                }
                out.push_str("<user>");
                cursor = after + end_rel;
            }
            None => {
                // Marker is the last segment and there's no closing sep —
                // still redact the trailing user name.
                if !input[after..].is_empty() {
                    out.push_str("<user>");
                }
                cursor = input.len();
            }
        }
    }
    out.push_str(&input[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_windows_user_path() {
        let s = "Path: C:\\Users\\Evelyn\\AppData\\Local\\Roblox";
        assert_eq!(
            redact_user_paths(s),
            "Path: C:\\Users\\<user>\\AppData\\Local\\Roblox"
        );
    }

    #[test]
    fn redacts_macos_user_path() {
        let s = "Path: /Users/evelyn/Library/Roblox";
        assert_eq!(redact_user_paths(s), "Path: /Users/<user>/Library/Roblox");
    }

    #[test]
    fn redacts_multiple_occurrences() {
        let s = "a /Users/alice/x and b /Users/bob/y";
        assert_eq!(
            redact_user_paths(s),
            "a /Users/<user>/x and b /Users/<user>/y"
        );
    }

    #[test]
    fn redacts_trailing_username_without_separator() {
        let s = "home: /Users/evelyn";
        assert_eq!(redact_user_paths(s), "home: /Users/<user>");
    }

    #[test]
    fn leaves_unrelated_paths_untouched() {
        let s = "module: kernel32.dll; addr: 0x1234";
        assert_eq!(redact_user_paths(s), s);
    }

    #[test]
    fn is_idempotent() {
        let s = "Path: C:\\Users\\Evelyn\\x";
        let once = redact_user_paths(s);
        let twice = redact_user_paths(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn redacts_linux_home_path() {
        let s = "/home/alice/config.json";
        assert_eq!(redact_user_paths(s), "/home/<user>/config.json");
    }
}
