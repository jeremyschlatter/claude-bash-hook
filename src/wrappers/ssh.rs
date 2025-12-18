//! ssh wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap ssh command
/// ssh [options] [user@]hostname [command]
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let mut host = None;
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_host = false;

    let opts_with_args = [
        "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p",
        "-Q", "-R", "-S", "-W", "-w",
    ];

    for arg in &cmd.args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if !found_host {
            if arg.starts_with('-') {
                let opt = if arg.len() > 2 { &arg[0..2] } else { arg.as_str() };
                if opts_with_args.contains(&opt) {
                    if arg.len() == 2 {
                        skip_next = true;
                    }
                }
                continue;
            }

            found_host = true;
            let h = if let Some(at_pos) = arg.find('@') {
                &arg[at_pos + 1..]
            } else {
                arg.as_str()
            };
            host = Some(h.to_string());
            continue;
        }

        inner_parts.push(arg.clone());
    }

    Some(UnwrapResult {
        inner_command: if inner_parts.is_empty() {
            None
        } else {
            Some(inner_parts.join(" "))
        },
        host,
        wrapper: "ssh".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "ssh".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("ssh {}", args.join(" ")),
        }
    }

    #[test]
    fn test_ssh_with_command() {
        let cmd = make_cmd(&["user@host", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_ssh_with_options() {
        let cmd = make_cmd(&["-p", "22", "-i", "key.pem", "host", "whoami"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
        assert_eq!(result.inner_command, Some("whoami".to_string()));
    }

    #[test]
    fn test_ssh_no_command() {
        let cmd = make_cmd(&["user@myhost"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("myhost".to_string()));
        assert_eq!(result.inner_command, None);
    }
}
