//! timeout wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap timeout command
/// timeout [options] DURATION COMMAND [args...]
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_duration = false;
    let mut found_command = false;

    let opts_with_args = ["-k", "--kill-after", "-s", "--signal"];

    for arg in &cmd.args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if found_command {
            inner_parts.push(arg.clone());
            continue;
        }

        if arg.starts_with('-') {
            let opt = if arg.contains('=') {
                continue;
            } else {
                arg.as_str()
            };
            if opts_with_args.contains(&opt) {
                skip_next = true;
            }
            continue;
        }

        if !found_duration {
            // First positional arg is duration, skip it
            found_duration = true;
            continue;
        }

        // This is the command
        found_command = true;
        inner_parts.push(arg.clone());
    }

    if inner_parts.is_empty() {
        return None;
    }

    Some(UnwrapResult {
        inner_command: Some(inner_parts.join(" ")),
        host: None,
        wrapper: "timeout".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "timeout".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("timeout {}", args.join(" ")),
        }
    }

    #[test]
    fn test_timeout_simple() {
        let cmd = make_cmd(&["30", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_timeout_with_options() {
        let cmd = make_cmd(&["-k", "10", "30s", "rm", "-rf", "/tmp"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("rm -rf /tmp".to_string()));
    }

    #[test]
    fn test_timeout_with_signal() {
        let cmd = make_cmd(&["-s", "KILL", "5", "sleep", "100"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("sleep 100".to_string()));
    }
}
