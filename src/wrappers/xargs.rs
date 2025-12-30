//! xargs wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap xargs command
/// xargs [options] [command [args...]]
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_command = false;

    // Options that take an argument
    let opts_with_args = [
        "-I",
        "--replace",
        "-n",
        "--max-args",
        "-P",
        "--max-procs",
        "-L",
        "--max-lines",
        "-s",
        "--max-chars",
        "-d",
        "--delimiter",
        "-a",
        "--arg-file",
        "-E",
    ];

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
            // Check if this option takes an argument
            let opt = if arg.contains('=') {
                // --flag=value format, no need to skip next
                continue;
            } else {
                arg.as_str()
            };

            if opts_with_args.contains(&opt) {
                skip_next = true;
            }
            continue;
        }

        // First non-option is the command
        found_command = true;
        inner_parts.push(arg.clone());
    }

    if inner_parts.is_empty() {
        // xargs with no command defaults to echo, which is allowed
        return Some(UnwrapResult {
            inner_command: Some("echo".to_string()),
            host: None,
            wrapper: "xargs".to_string(),
        });
    }

    Some(UnwrapResult {
        inner_command: Some(inner_parts.join(" ")),
        host: None,
        wrapper: "xargs".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "xargs".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("xargs {}", args.join(" ")),
        }
    }

    #[test]
    fn test_xargs_simple() {
        let cmd = make_cmd(&["grep", "-l", "pattern"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("grep -l pattern".to_string()));
    }

    #[test]
    fn test_xargs_with_replace() {
        let cmd = make_cmd(&["-I{}", "cp", "{}", "/tmp/"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("cp {} /tmp/".to_string()));
    }

    #[test]
    fn test_xargs_with_max_args() {
        let cmd = make_cmd(&["-n", "1", "rm"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("rm".to_string()));
    }

    #[test]
    fn test_xargs_no_command() {
        let cmd = make_cmd(&["-n", "1"]);
        let result = unwrap(&cmd).unwrap();
        // xargs defaults to echo when no command specified
        assert_eq!(result.inner_command, Some("echo".to_string()));
    }

    #[test]
    fn test_xargs_with_parallel() {
        let cmd = make_cmd(&["-P", "4", "-I{}", "convert", "{}", "{}.png"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("convert {} {}.png".to_string()));
    }

    #[test]
    fn test_xargs_dangerous_command() {
        let cmd = make_cmd(&["rm", "-rf"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("rm -rf".to_string()));
    }
}
