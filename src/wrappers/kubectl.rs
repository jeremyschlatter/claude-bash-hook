//! kubectl exec wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap kubectl exec command
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    if cmd.args.first().map(|s| s.as_str()) != Some("exec") {
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
        wrapper: "kubectl exec".to_string(),
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
}
