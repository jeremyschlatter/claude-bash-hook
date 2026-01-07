//! docker exec, docker compose exec, and docker compose run wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap docker exec, docker compose exec, or docker compose run command
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    // Check for docker exec
    if cmd.args.first().map(|s| s.as_str()) == Some("exec") {
        return unwrap_exec(&cmd.args[1..], "docker exec");
    }

    // Check for docker compose exec or run
    if cmd.args.first().map(|s| s.as_str()) == Some("compose") {
        match cmd.args.get(1).map(|s| s.as_str()) {
            Some("exec") => return unwrap_exec(&cmd.args[2..], "docker compose exec"),
            Some("run") => return unwrap_compose_run(&cmd.args[2..]),
            _ => return None,
        }
    }

    None
}

/// Unwrap exec-style commands: [OPTIONS] CONTAINER/SERVICE COMMAND [ARG...]
fn unwrap_exec(args: &[String], wrapper_name: &str) -> Option<UnwrapResult> {
    // Options that take an argument
    let opts_with_args = [
        "-e",
        "--env",
        "-u",
        "--user",
        "-w",
        "--workdir",
        "--env-file",
        "--index",
    ];

    let mut skip_next = false;
    let mut found_container = false;
    let mut inner_parts = Vec::new();

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if !found_container {
            if arg.starts_with('-') {
                // Handle --opt=value format
                if arg.contains('=') {
                    continue;
                }
                // Check if this option takes an argument
                if opts_with_args.iter().any(|o| *o == arg) {
                    skip_next = true;
                }
                continue;
            }

            // First non-option is the container/service name
            found_container = true;
            continue;
        }

        // Everything after container name is the command
        inner_parts.push(arg.clone());
    }

    let inner_command = if inner_parts.is_empty() {
        None
    } else {
        Some(inner_parts.join(" "))
    };

    Some(UnwrapResult {
        inner_command,
        host: None,
        wrapper: wrapper_name.to_string(),
    })
}

/// Unwrap docker compose run: [OPTIONS] SERVICE [COMMAND] [ARG...]
fn unwrap_compose_run(args: &[String]) -> Option<UnwrapResult> {
    // Options that take an argument for docker compose run
    let opts_with_args = [
        "-e",
        "--env",
        "-u",
        "--user",
        "-w",
        "--workdir",
        "--entrypoint",
        "-v",
        "--volume",
        "-p",
        "--publish",
        "--name",
        "-l",
        "--label",
    ];

    let mut skip_next = false;
    let mut found_service = false;
    let mut inner_parts = Vec::new();

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if !found_service {
            if arg.starts_with('-') {
                // Handle --opt=value format
                if arg.contains('=') {
                    continue;
                }
                // Check if this option takes an argument
                if opts_with_args.iter().any(|o| *o == arg) {
                    skip_next = true;
                }
                continue;
            }

            // First non-option is the service name
            found_service = true;
            continue;
        }

        // Everything after service name is the command
        inner_parts.push(arg.clone());
    }

    let inner_command = if inner_parts.is_empty() {
        None
    } else {
        Some(inner_parts.join(" "))
    };

    Some(UnwrapResult {
        inner_command,
        host: None,
        wrapper: "docker compose run".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "docker".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("docker {}", args.join(" ")),
        }
    }

    // docker exec tests
    #[test]
    fn test_docker_exec_simple() {
        let cmd = make_cmd(&["exec", "mycontainer", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
        assert_eq!(result.wrapper, "docker exec");
    }

    #[test]
    fn test_docker_exec_with_options() {
        let cmd = make_cmd(&["exec", "-it", "-u", "root", "mycontainer", "bash"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("bash".to_string()));
    }

    #[test]
    fn test_docker_exec_with_env() {
        let cmd = make_cmd(&[
            "exec",
            "-e",
            "FOO=bar",
            "mycontainer",
            "cat",
            "/etc/nginx/nginx.conf",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(
            result.inner_command,
            Some("cat /etc/nginx/nginx.conf".to_string())
        );
    }

    #[test]
    fn test_docker_exec_with_workdir() {
        let cmd = make_cmd(&["exec", "-w", "/app", "mycontainer", "pwd"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("pwd".to_string()));
    }

    #[test]
    fn test_docker_exec_no_command() {
        let cmd = make_cmd(&["exec", "mycontainer"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, None);
    }

    // docker compose exec tests
    #[test]
    fn test_docker_compose_exec_simple() {
        let cmd = make_cmd(&["compose", "exec", "web", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
        assert_eq!(result.wrapper, "docker compose exec");
    }

    #[test]
    fn test_docker_compose_exec_with_options() {
        let cmd = make_cmd(&["compose", "exec", "-u", "root", "web", "bash"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("bash".to_string()));
    }

    // docker compose run tests
    #[test]
    fn test_docker_compose_run_simple() {
        let cmd = make_cmd(&["compose", "run", "web", "python", "manage.py", "migrate"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(
            result.inner_command,
            Some("python manage.py migrate".to_string())
        );
        assert_eq!(result.wrapper, "docker compose run");
    }

    #[test]
    fn test_docker_compose_run_with_options() {
        let cmd = make_cmd(&["compose", "run", "--rm", "-e", "DEBUG=1", "web", "pytest"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("pytest".to_string()));
    }

    #[test]
    fn test_docker_compose_run_no_command() {
        let cmd = make_cmd(&["compose", "run", "web"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, None);
    }

    // Not a wrapper tests
    #[test]
    fn test_docker_run_not_wrapper() {
        let cmd = make_cmd(&["run", "ubuntu", "ls"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_docker_ps_not_wrapper() {
        let cmd = make_cmd(&["ps"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_docker_compose_ps_not_wrapper() {
        let cmd = make_cmd(&["compose", "ps"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }
}
