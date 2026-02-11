//! Shared path utilities
//!
//! Pure-Rust equivalent of `realpath -m` and cross-platform /tmp handling.

use std::path::{Component, Path, PathBuf};

/// Resolve a path without requiring all components to exist.
/// Equivalent to `realpath -m`: follows symlinks for existing components,
/// then resolves `.` and `..` lexically for the rest.
pub fn resolve_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }

    let input = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        std::env::current_dir().ok()?.join(path)
    };

    let mut resolved = PathBuf::from("/");

    for component in input.components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(c) => {
                let candidate = resolved.join(c);
                resolved = candidate.canonicalize().unwrap_or(candidate);
            }
            Component::Prefix(_) => {}
        }
    }

    resolved.to_str().map(|s| s.to_string())
}

/// Returns the portion of a path below /tmp/ (or /private/tmp/ on macOS).
/// Returns None if path is not under /tmp or has nothing meaningful after the prefix.
pub fn under_tmp(path: &str) -> Option<&str> {
    let after = if let Some(rest) = path.strip_prefix("/tmp/") {
        rest
    } else if cfg!(target_os = "macos") {
        path.strip_prefix("/private/tmp/")?
    } else {
        return None;
    };

    if after.is_empty() || after.chars().all(|c| c == '/') {
        return None;
    }

    Some(after)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use /usr/nonexistent paths to avoid /tmp symlink differences between Linux and macOS

    #[test]
    fn test_resolve_absolute_simple() {
        assert_eq!(
            resolve_path("/usr/nonexistent/foo").unwrap(),
            "/usr/nonexistent/foo"
        );
    }

    #[test]
    fn test_resolve_absolute_with_dotdot() {
        assert_eq!(
            resolve_path("/usr/nonexistent/../other").unwrap(),
            "/usr/other"
        );
    }

    #[test]
    fn test_resolve_absolute_with_dot() {
        assert_eq!(
            resolve_path("/usr/./nonexistent").unwrap(),
            "/usr/nonexistent"
        );
    }

    #[test]
    fn test_resolve_dotdot_past_root() {
        assert_eq!(resolve_path("/../../usr/foo").unwrap(), "/usr/foo");
    }

    #[test]
    fn test_resolve_follows_symlinks() {
        // /tmp is a symlink to /private/tmp on macOS; not on Linux
        let resolved = resolve_path("/tmp").unwrap();
        assert!(resolved == "/tmp" || resolved == "/private/tmp");
    }

    #[test]
    fn test_resolve_empty_returns_none() {
        assert!(resolve_path("").is_none());
    }

    #[test]
    fn test_under_tmp_basic() {
        assert_eq!(under_tmp("/tmp/foo"), Some("foo"));
    }

    #[test]
    fn test_under_tmp_nested() {
        assert_eq!(under_tmp("/tmp/claude/x"), Some("claude/x"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_under_tmp_private() {
        assert_eq!(under_tmp("/private/tmp/foo"), Some("foo"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_under_tmp_private_nested() {
        assert_eq!(under_tmp("/private/tmp/claude/x"), Some("claude/x"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_under_tmp_private_not_matched_on_linux() {
        assert_eq!(under_tmp("/private/tmp/foo"), None);
    }

    #[test]
    fn test_under_tmp_bare() {
        assert_eq!(under_tmp("/tmp"), None);
    }

    #[test]
    fn test_under_tmp_trailing_slash() {
        assert_eq!(under_tmp("/tmp/"), None);
    }

    #[test]
    fn test_under_tmp_only_slashes() {
        assert_eq!(under_tmp("/tmp///"), None);
    }

    #[test]
    fn test_under_tmp_not_tmp() {
        assert_eq!(under_tmp("/home/foo"), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_under_tmp_private_bare() {
        assert_eq!(under_tmp("/private/tmp"), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_under_tmp_private_trailing_slash() {
        assert_eq!(under_tmp("/private/tmp/"), None);
    }
}
