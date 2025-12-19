//! SQL query analysis for mysql/mariadb commands

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};

/// Check if a mysql/mariadb command has a read-only query
pub fn check_sql_query(cmd: &Command) -> Option<PermissionResult> {
    // Find the -e argument
    let mut query = None;
    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-e" || arg == "--execute" {
            query = iter.next().map(|s| s.as_str());
            break;
        } else if arg.starts_with("-e") {
            // -e"query" format
            query = Some(&arg[2..]);
            break;
        } else if arg.starts_with("--execute=") {
            query = Some(&arg[10..]);
            break;
        }
    }

    let query = query?;
    // Strip surrounding quotes if present
    let query = query.trim();
    let query = query.strip_prefix('"').unwrap_or(query);
    let query = query.strip_suffix('"').unwrap_or(query);
    let query = query.strip_prefix('\'').unwrap_or(query);
    let query = query.strip_suffix('\'').unwrap_or(query);

    // Read-only SQL statements
    let read_only_prefixes = [
        "SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "USE",
    ];

    // Split by semicolons and check ALL statements
    // If any statement is not read-only, ask for permission
    for statement in query.split(';') {
        let trimmed = statement.trim().to_uppercase();
        if trimmed.is_empty() {
            continue;
        }
        if !read_only_prefixes.iter().any(|p| trimmed.starts_with(p)) {
            // Found a non-read-only statement
            return Some(PermissionResult {
                permission: Permission::Ask,
                reason: "SQL write operation".to_string(),
                suggestion: None,
            });
        }
    }

    // All statements are read-only
    Some(PermissionResult {
        permission: Permission::Allow,
        reason: "read-only SQL query".to_string(),
        suggestion: None,
    })
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
    fn test_select_allowed() {
        let cmd = make_cmd("mysql", &["-u", "root", "-e", "SELECT * FROM users"]);
        let result = check_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_select_with_quotes_allowed() {
        // Tree-sitter includes quotes in string arguments
        let cmd = make_cmd("mysql", &["-e", "\"SELECT * FROM users\""]);
        let result = check_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_show_allowed() {
        let cmd = make_cmd("mariadb", &["-e", "SHOW DATABASES"]);
        let result = check_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_describe_allowed() {
        let cmd = make_cmd("mysql", &["-e", "DESCRIBE users"]);
        let result = check_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_insert_asks() {
        let cmd = make_cmd("mysql", &["-e", "INSERT INTO users VALUES (1, 'test')"]);
        let result = check_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_delete_asks() {
        let cmd = make_cmd("mariadb", &["-e", "DELETE FROM users WHERE id = 1"]);
        let result = check_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_update_asks() {
        let cmd = make_cmd("mysql", &["-e", "UPDATE users SET name = 'foo'"]);
        let result = check_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_no_query_returns_none() {
        let cmd = make_cmd("mysql", &["-u", "root", "dbname"]);
        let result = check_sql_query(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_execute_long_form() {
        let cmd = make_cmd("mysql", &["--execute", "SELECT 1"]);
        let result = check_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_execute_equals_form() {
        let cmd = make_cmd("mysql", &["--execute=SHOW TABLES"]);
        let result = check_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_multi_statement_bypass_blocked() {
        // SELECT followed by DROP should NOT be allowed
        let cmd = make_cmd("mysql", &["-e", "SELECT 1; DROP TABLE users;"]);
        let result = check_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_multi_statement_all_readonly() {
        // Multiple read-only statements should be allowed
        let cmd = make_cmd("mysql", &["-e", "SELECT 1; SHOW TABLES; DESCRIBE users;"]);
        let result = check_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
