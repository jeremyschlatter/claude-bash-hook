//! Python inline script analysis for `python -c` commands

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};

/// Dangerous Python functions/modules that have side effects
const DANGEROUS_PATTERNS: &[&str] = &[
    // Command execution
    "subprocess",
    "os.system",
    "os.popen",
    "os.spawn",
    "os.exec",
    "commands.",
    // Code execution
    "eval(",
    "exec(",
    "compile(",
    "__import__",
    // File writing
    "open(", // We'll check for write modes separately
    "file(",
    // File operations
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.mkdir",
    "os.makedirs",
    "os.rename",
    "os.replace",
    "os.truncate",
    "os.write",
    "shutil.",
    "pathlib.Path.write",
    "pathlib.Path.mkdir",
    "pathlib.Path.rmdir",
    "pathlib.Path.unlink",
    "pathlib.Path.rename",
    "pathlib.Path.touch",
    // Network
    "socket.",
    "urllib.request.urlopen",
    "http.client",
    "ftplib",
    "smtplib",
    "requests.",
    "httpx.",
    "aiohttp.",
    // Database
    "sqlite3.connect",
    "psycopg",
    "pymysql",
    "mysql.connector",
    // Process control
    "signal.",
    "os.kill",
    "os.killpg",
    // Environment modification
    "os.putenv",
    "os.unsetenv",
    "os.environ[",
    "os.chdir",
    "os.fchdir",
];

/// Extract Python code from python -c command
fn extract_python_code(cmd: &Command) -> Option<&str> {
    let mut iter = cmd.args.iter();

    while let Some(arg) = iter.next() {
        if arg == "-c" {
            // Next arg is the code
            return iter.next().map(|s| s.as_str());
        }
        // Handle -c"code" (no space)
        if let Some(code) = arg.strip_prefix("-c") {
            if !code.is_empty() {
                return Some(code);
            }
        }
    }

    None
}

/// Check if open() is used in read-only mode
fn has_write_open(code: &str) -> bool {
    // Look for open() calls and check if they have write modes
    let code_lower = code.to_lowercase();

    // Find all open( occurrences
    let mut pos = 0;
    while let Some(idx) = code_lower[pos..].find("open(") {
        let start = pos + idx;
        // Look at the content after open(
        let after_open = &code[start + 5..];

        // Find the closing paren (simple heuristic)
        if let Some(close) = after_open.find(')') {
            let args = &after_open[..close];
            // Check for write modes: 'w', 'a', 'x', 'r+', 'w+', 'a+'
            // But not just 'r' or 'rb'
            if args.contains("'w")
                || args.contains("\"w")
                || args.contains("'a")
                || args.contains("\"a")
                || args.contains("'x")
                || args.contains("\"x")
                || args.contains("'+")
                || args.contains("\"+")
                || args.contains("mode='w")
                || args.contains("mode=\"w")
                || args.contains("mode='a")
                || args.contains("mode=\"a")
            {
                return true;
            }
        }
        pos = start + 5;
    }

    false
}

/// Check if Python code only uses read-only operations
fn is_readonly_python(code: &str) -> bool {
    let code_lower = code.to_lowercase();

    // Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS {
        let pattern_lower = pattern.to_lowercase();

        // Special handling for open() - check mode
        if *pattern == "open(" {
            if code_lower.contains("open(") && has_write_open(code) {
                return false;
            }
            continue;
        }

        if code_lower.contains(&pattern_lower) {
            return false;
        }
    }

    true
}

/// Check if a python command is read-only
pub fn check_python_script(cmd: &Command) -> Option<PermissionResult> {
    // Match python, python3, python3.x
    if !cmd.name.starts_with("python") {
        return None;
    }

    // Only handle -c flag
    let code = extract_python_code(cmd)?;

    if is_readonly_python(code) {
        Some(PermissionResult {
            permission: Permission::Allow,
            reason: "read-only Python script".to_string(),
            suggestion: None,
        })
    } else {
        Some(PermissionResult {
            permission: Permission::Ask,
            reason: "Python script may have side effects".to_string(),
            suggestion: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(name: &str, args: &[&str]) -> Command {
        Command {
            name: name.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("{} {}", name, args.join(" ")),
        }
    }

    #[test]
    fn test_print_allowed() {
        let cmd = make_cmd("python3", &["-c", "print('hello')"]);
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_json_loads_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import json; print(json.loads('{\"a\": 1}'))"],
        );
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sys_version_allowed() {
        let cmd = make_cmd("python", &["-c", "import sys; print(sys.version)"]);
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_base64_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import base64; print(base64.b64decode('aGVsbG8='))"],
        );
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_os_path_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import os.path; print(os.path.basename('/tmp/foo'))"],
        );
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_read_file_allowed() {
        let cmd = make_cmd("python3", &["-c", "print(open('/etc/hosts').read())"]);
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_read_file_explicit_mode_allowed() {
        let cmd = make_cmd("python3", &["-c", "print(open('/etc/hosts', 'r').read())"]);
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_write_file_asks() {
        let cmd = make_cmd("python3", &["-c", "open('/tmp/test', 'w').write('data')"]);
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_append_file_asks() {
        let cmd = make_cmd("python3", &["-c", "open('/tmp/test', 'a').write('data')"]);
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_subprocess_asks() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import subprocess; subprocess.run(['ls'])"],
        );
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_os_system_asks() {
        let cmd = make_cmd("python3", &["-c", "import os; os.system('ls')"]);
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_os_remove_asks() {
        let cmd = make_cmd("python3", &["-c", "import os; os.remove('/tmp/test')"]);
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_eval_asks() {
        let cmd = make_cmd("python3", &["-c", "eval('print(1)')"]);
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_exec_asks() {
        let cmd = make_cmd("python3", &["-c", "exec('print(1)')"]);
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_shutil_asks() {
        let cmd = make_cmd("python3", &["-c", "import shutil; shutil.copy('a', 'b')"]);
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_requests_asks() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import requests; requests.get('http://example.com')"],
        );
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_not_python_returns_none() {
        let cmd = Command {
            name: "ruby".to_string(),
            args: vec!["-e".to_string(), "puts 'hello'".to_string()],
            text: "ruby -e puts 'hello'".to_string(),
        };
        let result = check_python_script(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_python_without_c_returns_none() {
        let cmd = make_cmd("python3", &["script.py"]);
        let result = check_python_script(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_complex_readonly_allowed() {
        let cmd = make_cmd(
            "python3",
            &[
                "-c",
                "import json, sys; data = json.loads(sys.stdin.read()); print(len(data))",
            ],
        );
        let result = check_python_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
