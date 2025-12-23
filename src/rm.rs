//! rm command special handling
//!
//! Auto-allows rm for files under /tmp/ (but not /tmp itself)

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};
use std::process::Command as ProcessCommand;

/// Check if an rm command should be auto-allowed
/// Allows deletion of files under /tmp/ but not /tmp itself
pub fn check_rm(cmd: &Command) -> Option<PermissionResult> {
    if cmd.name != "rm" {
        return None;
    }

    // Extract file arguments (skip flags)
    let file_args: Vec<&str> = cmd
        .args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
        .collect();

    // No files specified - let normal handling deal with it
    if file_args.is_empty() {
        return None;
    }

    // Check each file argument
    for path in &file_args {
        if !is_safe_tmp_path(path) {
            // Not a safe /tmp path - passthrough to normal handling
            return None;
        }
    }

    // All paths are safe /tmp paths
    Some(PermissionResult {
        permission: Permission::Allow,
        reason: "rm in /tmp".to_string(),
        suggestion: None,
    })
}

/// Check if a path is safely under /tmp/ (not /tmp itself)
fn is_safe_tmp_path(path: &str) -> bool {
    // Quick sanity checks before running realpath
    // Reject empty paths
    if path.is_empty() {
        return false;
    }

    // Reject paths with null bytes or other suspicious characters
    if path.contains('\0') || path.contains('\n') {
        return false;
    }

    // Use realpath to resolve the path
    // This handles symlinks, .., and other tricks
    let resolved = match resolve_path(path) {
        Some(p) => p,
        None => {
            // realpath failed - path might not exist
            // Try to check the parent directory for paths that don't exist yet
            if let Some(parent) = std::path::Path::new(path).parent() {
                if let Some(parent_str) = parent.to_str() {
                    if !parent_str.is_empty() {
                        if let Some(resolved_parent) = resolve_path(parent_str) {
                            // Check if parent is under /tmp
                            return is_under_tmp(&resolved_parent);
                        }
                    }
                }
            }
            return false;
        }
    };

    is_under_tmp(&resolved)
}

/// Check if a resolved path is under /tmp/ (not /tmp itself)
fn is_under_tmp(resolved: &str) -> bool {
    // Must start with /tmp/
    if !resolved.starts_with("/tmp/") {
        return false;
    }

    // Must have something after /tmp/
    let after_tmp = &resolved[5..]; // len("/tmp/") = 5
    if after_tmp.is_empty() {
        return false;
    }

    // Reject if it's just /tmp/ with trailing slashes
    if after_tmp.chars().all(|c| c == '/') {
        return false;
    }

    true
}

/// Resolve a path using realpath
fn resolve_path(path: &str) -> Option<String> {
    let output = ProcessCommand::new("realpath")
        .arg("-m") // don't require path to exist
        .arg("--")
        .arg(path)
        .output()
        .ok()?;

    if output.status.success() {
        let resolved = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !resolved.is_empty() {
            return Some(resolved);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "rm".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("rm {}", args.join(" ")),
        }
    }

    #[test]
    fn test_rm_tmp_file() {
        let cmd = make_cmd(&["/tmp/test.txt"]);
        let result = check_rm(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_tmp_subdir() {
        let cmd = make_cmd(&["-rf", "/tmp/mydir/subdir"]);
        let result = check_rm(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_tmp_itself_not_allowed() {
        let cmd = make_cmd(&["-rf", "/tmp"]);
        let result = check_rm(&cmd);
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_tmp_slash_not_allowed() {
        let cmd = make_cmd(&["-rf", "/tmp/"]);
        let result = check_rm(&cmd);
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_home_not_allowed() {
        let cmd = make_cmd(&["/home/user/file"]);
        let result = check_rm(&cmd);
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_relative_path() {
        let cmd = make_cmd(&["./somefile"]);
        let result = check_rm(&cmd);
        // Likely not under /tmp, so passthrough
        assert!(result.is_none());
    }

    #[test]
    fn test_rm_multiple_tmp_files() {
        let cmd = make_cmd(&["/tmp/a", "/tmp/b", "/tmp/c"]);
        let result = check_rm(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_mixed_paths_not_allowed() {
        let cmd = make_cmd(&["/tmp/a", "/home/user/b"]);
        let result = check_rm(&cmd);
        assert!(result.is_none()); // passthrough because /home path
    }

    #[test]
    fn test_not_rm_command() {
        let cmd = Command {
            name: "ls".to_string(),
            args: vec!["/tmp".to_string()],
            text: "ls /tmp".to_string(),
        };
        let result = check_rm(&cmd);
        assert!(result.is_none());
    }
}
