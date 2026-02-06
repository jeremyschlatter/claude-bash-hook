//! gcloud compute ssh wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Strip surrounding single or double quotes from a string
fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Unwrap gcloud compute ssh command
/// gcloud compute ssh [options] INSTANCE [-- COMMAND]
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    // Must be: gcloud compute ssh ...
    if cmd.args.len() < 2 || cmd.args[0] != "compute" || cmd.args[1] != "ssh" {
        return None;
    }

    let args = &cmd.args[2..];
    let mut host = None;
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_separator = false;

    // Options that take an argument
    let opts_with_args = [
        "--zone",
        "--project",
        "--tunnel-through-iap",
        "--internal-ip",
        "--ssh-key-file",
        "--ssh-flag",
        "--command",
    ];

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }

        // After -- everything is the command
        if found_separator {
            inner_parts.push(arg.clone());
            continue;
        }

        if arg == "--" {
            found_separator = true;
            continue;
        }

        if arg.starts_with('-') {
            // Handle --opt=value format
            if arg.contains('=') {
                continue;
            }
            // Check if this option takes an argument
            if opts_with_args.iter().any(|o| arg.starts_with(o)) {
                skip_next = true;
            }
            continue;
        }

        // Non-flag, non-separator: this is the instance name (host)
        if host.is_none() {
            host = Some(arg.clone());
        }
    }

    let inner_command = if inner_parts.is_empty() {
        None
    } else if inner_parts.len() == 1 {
        Some(strip_quotes(&inner_parts[0]))
    } else {
        Some(inner_parts.join(" "))
    };

    Some(UnwrapResult {
        inner_command,
        host,
        wrapper: "gcloud compute ssh".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "gcloud".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("gcloud {}", args.join(" ")),
        }
    }

    #[test]
    fn test_gcloud_compute_ssh_with_command() {
        let cmd = make_cmd(&["compute", "ssh", "my-instance", "--", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("my-instance".to_string()));
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_gcloud_compute_ssh_with_zone() {
        let cmd = make_cmd(&[
            "compute",
            "ssh",
            "--zone",
            "us-central1-a",
            "my-instance",
            "--",
            "whoami",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("my-instance".to_string()));
        assert_eq!(result.inner_command, Some("whoami".to_string()));
    }

    #[test]
    fn test_gcloud_compute_ssh_no_command() {
        let cmd = make_cmd(&["compute", "ssh", "my-instance"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("my-instance".to_string()));
        assert_eq!(result.inner_command, None);
    }

    #[test]
    fn test_gcloud_compute_ssh_with_project() {
        let cmd = make_cmd(&[
            "compute",
            "ssh",
            "--project=my-project",
            "--zone=us-east1-b",
            "instance-1",
            "--",
            "docker",
            "ps",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("instance-1".to_string()));
        assert_eq!(result.inner_command, Some("docker ps".to_string()));
    }

    #[test]
    fn test_not_gcloud_compute_ssh() {
        let cmd = make_cmd(&["compute", "instances", "list"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_gcloud_other_command() {
        let cmd = make_cmd(&["auth", "list"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }
}
