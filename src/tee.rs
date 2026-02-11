//! tee command special handling
//!
//! Auto-allows tee for files under /tmp/

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};
use crate::paths;

/// Check if a tee command should be auto-allowed
/// Allows writing to files under /tmp/
pub fn check_tee(cmd: &Command, _initial_cwd: Option<&str>) -> Option<PermissionResult> {
    if cmd.name != "tee" {
        return None;
    }

    // Extract file arguments (skip flags)
    let file_args: Vec<&str> = cmd
        .args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
        .collect();

    // No files specified - allow (tee with no args just copies stdin to stdout)
    if file_args.is_empty() {
        return Some(PermissionResult {
            permission: Permission::Allow,
            reason: "tee with no output file".to_string(),
            suggestion: None,
        });
    }

    // Check each file argument
    for path in &file_args {
        if !is_safe_tmp_path(path) {
            return None;
        }
    }

    Some(PermissionResult {
        permission: Permission::Allow,
        reason: "tee to /tmp".to_string(),
        suggestion: None,
    })
}

/// Check if a path is safely under /tmp/
fn is_safe_tmp_path(path: &str) -> bool {
    // Quick sanity checks before running realpath
    if path.is_empty() {
        return false;
    }

    // Reject paths with null bytes or other suspicious characters
    if path.contains('\0') || path.contains('\n') {
        return false;
    }

    let resolved = match paths::resolve_path(path) {
        Some(p) => p,
        None => {
            // resolve failed - path might not exist
            // Try to check the parent directory for paths that don't exist yet
            if let Some(parent) = std::path::Path::new(path).parent() {
                if let Some(parent_str) = parent.to_str() {
                    if !parent_str.is_empty() {
                        if let Some(resolved_parent) = paths::resolve_path(parent_str) {
                            return paths::under_tmp(&resolved_parent).is_some();
                        }
                    }
                }
            }
            return false;
        }
    };

    paths::under_tmp(&resolved).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "tee".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("tee {}", args.join(" ")),
        }
    }

    #[test]
    fn test_tee_tmp_file() {
        let cmd = make_cmd(&["/tmp/test.log"]);
        let result = check_tee(&cmd, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_tee_tmp_claude_file() {
        let cmd = make_cmd(&["/tmp/claude/test.log"]);
        let result = check_tee(&cmd, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_tee_home_not_allowed() {
        let cmd = make_cmd(&["/home/user/file.log"]);
        let result = check_tee(&cmd, None);
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_tee_no_args() {
        let cmd = make_cmd(&[]);
        let result = check_tee(&cmd, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_tee_with_append_flag() {
        let cmd = make_cmd(&["-a", "/tmp/test.log"]);
        let result = check_tee(&cmd, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_not_tee_command() {
        let cmd = Command {
            name: "cat".to_string(),
            args: vec!["/tmp/test.log".to_string()],
            text: "cat /tmp/test.log".to_string(),
        };
        let result = check_tee(&cmd, None);
        assert!(result.is_none());
    }
}
