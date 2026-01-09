//! kubectl exec/debug wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap kubectl exec or debug command
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let subcommand = cmd.args.first().map(|s| s.as_str())?;
    if subcommand != "exec" && subcommand != "debug" {
        return None;
    }

    let separator_pos = cmd.args.iter().position(|arg| arg == "--");

    let inner_command = match separator_pos {
        Some(pos) => {
            let inner_parts: Vec<_> = cmd.args[pos + 1..].to_vec();
            if inner_parts.is_empty() {
                None
            } else {
                Some(inner_parts.join(" "))
            }
        }
        None => None,
    };

    Some(UnwrapResult {
        inner_command,
        host: None,
        wrapper: format!("kubectl {}", subcommand),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "kubectl".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("kubectl {}", args.join(" ")),
        }
    }

    #[test]
    fn test_kubectl_exec_simple() {
        let cmd = make_cmd(&["exec", "mypod", "--", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
        assert_eq!(result.wrapper, "kubectl exec");
    }

    #[test]
    fn test_kubectl_exec_with_options() {
        let cmd = make_cmd(&[
            "exec",
            "-it",
            "mypod",
            "-c",
            "mycontainer",
            "--",
            "/bin/bash",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("/bin/bash".to_string()));
    }

    #[test]
    fn test_kubectl_exec_with_namespace() {
        let cmd = make_cmd(&["exec", "-n", "prod", "mypod", "--", "rm", "-rf", "/tmp"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("rm -rf /tmp".to_string()));
    }

    #[test]
    fn test_kubectl_get_not_wrapper() {
        let cmd = make_cmd(&["get", "pods"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_kubectl_exec_no_separator() {
        let cmd = make_cmd(&["exec", "mypod"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, None);
    }

    #[test]
    fn test_kubectl_debug_simple() {
        let cmd = make_cmd(&["debug", "mypod", "--", "sh"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("sh".to_string()));
        assert_eq!(result.wrapper, "kubectl debug");
    }

    #[test]
    fn test_kubectl_debug_with_image() {
        let cmd = make_cmd(&[
            "debug",
            "-it",
            "mypod",
            "--image=busybox",
            "--",
            "cat",
            "/etc/hosts",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("cat /etc/hosts".to_string()));
        assert_eq!(result.wrapper, "kubectl debug");
    }

    #[test]
    fn test_kubectl_debug_no_separator() {
        let cmd = make_cmd(&["debug", "mypod", "--image=busybox"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, None);
    }
}
