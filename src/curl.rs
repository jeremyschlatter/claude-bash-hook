//! Curl command special handling - URL host extraction

use crate::analyzer::Command;
use crate::config::{Config, Permission, PermissionResult};

/// Extract host from a URL
fn extract_host(url: &str) -> Option<String> {
    // Strip quotes if present
    let url = url.trim_matches('"').trim_matches('\'');

    // Handle scheme://host/path
    let after_scheme = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        // No scheme - treat as host directly for simple cases
        url
    };

    // Extract host (before first / or end)
    let host_port = if let Some(pos) = after_scheme.find('/') {
        &after_scheme[..pos]
    } else {
        after_scheme
    };

    // Strip user@ prefix if present
    let host_port = if let Some(pos) = host_port.find('@') {
        &host_port[pos + 1..]
    } else {
        host_port
    };

    // Strip :port suffix if present
    let host = if let Some(pos) = host_port.rfind(':') {
        // Make sure this is actually a port (after last colon, all digits)
        let potential_port = &host_port[pos + 1..];
        if potential_port.chars().all(|c| c.is_ascii_digit()) {
            &host_port[..pos]
        } else {
            host_port
        }
    } else {
        host_port
    };

    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Check if a host is localhost
fn is_localhost(host: &str) -> bool {
    matches!(
        host,
        "localhost" | "127.0.0.1" | "::1" | "[::1]" | "0.0.0.0"
    ) || host.starts_with("127.")
        || host.ends_with(".localhost")
}

/// Check a curl command and extract URL hosts
/// Returns a permission result based on the URL host
pub fn check_curl(cmd: &Command, config: &Config) -> Option<PermissionResult> {
    if cmd.name != "curl" {
        return None;
    }

    // Options that take an argument (skip them when looking for URLs)
    let opts_with_args = [
        "-A",
        "--user-agent",
        "-b",
        "--cookie",
        "-c",
        "--cookie-jar",
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "-D",
        "--dump-header",
        "-e",
        "--referer",
        "-F",
        "--form",
        "-H",
        "--header",
        "-K",
        "--config",
        "-m",
        "--max-time",
        "-o",
        "--output",
        "-O",
        "--remote-name",
        "-T",
        "--upload-file",
        "-u",
        "--user",
        "-w",
        "--write-out",
        "-x",
        "--proxy",
        "-X",
        "--request",
        "--connect-timeout",
        "--retry",
        "--retry-delay",
        "--retry-max-time",
        "-r",
        "--range",
        "--resolve",
        "--interface",
        "-E",
        "--cert",
        "--key",
        "--cacert",
    ];

    let mut urls: Vec<String> = Vec::new();
    let mut skip_next = false;

    for arg in &cmd.args {
        if skip_next {
            skip_next = false;
            continue;
        }

        // Skip options
        if arg.starts_with('-') {
            // Check if this option takes an argument
            let opt = if arg.contains('=') {
                // --option=value - no need to skip next
                continue;
            } else if arg.len() > 2 && arg.starts_with('-') && !arg.starts_with("--") {
                // Combined short opts like -sL - check first char
                &arg[0..2]
            } else {
                arg.as_str()
            };

            if opts_with_args.contains(&opt) {
                skip_next = true;
            }
            continue;
        }

        // This looks like a URL
        urls.push(arg.clone());
    }

    if urls.is_empty() {
        // No URLs found - pass through to default handling
        return None;
    }

    // Check each URL's host
    let mut all_localhost = true;
    let mut hosts: Vec<String> = Vec::new();

    for url in &urls {
        if let Some(host) = extract_host(url) {
            hosts.push(host.clone());
            if !is_localhost(&host) {
                all_localhost = false;
            }
        }
    }

    // If all URLs are localhost, allow
    if all_localhost && !hosts.is_empty() {
        return Some(PermissionResult {
            permission: Permission::Allow,
            reason: format!("curl to localhost ({})", hosts.join(", ")),
            suggestion: None,
        });
    }

    // For non-localhost URLs, use check_host permission via config
    // Check if there's a curl rule with host_rules
    for host in &hosts {
        let result = config.check_command_with_host("curl", &cmd.args, Some(host));
        if result.permission != Permission::Passthrough {
            return Some(result);
        }
    }

    // No specific rule - pass through
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_simple() {
        assert_eq!(
            extract_host("http://localhost:3000/foo"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn test_extract_host_ip() {
        assert_eq!(
            extract_host("http://127.0.0.1:3000/debug"),
            Some("127.0.0.1".to_string())
        );
    }

    #[test]
    fn test_extract_host_external() {
        assert_eq!(
            extract_host("https://example.com/api"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_with_user() {
        assert_eq!(
            extract_host("http://user:pass@host.com/path"),
            Some("host.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_quoted() {
        assert_eq!(
            extract_host("\"http://localhost:8080/test\""),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn test_extract_host_no_port() {
        assert_eq!(
            extract_host("https://api.example.com/v1"),
            Some("api.example.com".to_string())
        );
    }

    #[test]
    fn test_is_localhost() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("127.0.0.1"));
        assert!(is_localhost("127.0.0.2"));
        assert!(is_localhost("::1"));
        assert!(is_localhost("foo.localhost"));
        assert!(!is_localhost("example.com"));
        assert!(!is_localhost("localhost.evil.com"));
    }

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "curl".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("curl {}", args.join(" ")),
        }
    }

    #[test]
    fn test_curl_localhost_allowed() {
        let config = Config::default();
        let cmd = make_cmd(&["-s", "http://127.0.0.1:3000/debug"]);
        let result = check_curl(&cmd, &config).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_curl_localhost_with_header() {
        let config = Config::default();
        let cmd = make_cmd(&[
            "-H",
            "Content-Type: application/json",
            "http://localhost:8080/api",
        ]);
        let result = check_curl(&cmd, &config).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_curl_external_no_rule() {
        let config = Config::default();
        let cmd = make_cmd(&["https://example.com/api"]);
        // No rule for external hosts - returns None (passthrough)
        let result = check_curl(&cmd, &config);
        assert!(result.is_none());
    }

    #[test]
    fn test_curl_no_url() {
        let config = Config::default();
        let cmd = make_cmd(&["--help"]);
        let result = check_curl(&cmd, &config);
        assert!(result.is_none());
    }

    #[test]
    fn test_not_curl() {
        let config = Config::default();
        let cmd = Command {
            name: "wget".to_string(),
            args: vec!["http://localhost".to_string()],
            text: "wget http://localhost".to_string(),
        };
        let result = check_curl(&cmd, &config);
        assert!(result.is_none());
    }
}
