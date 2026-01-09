//! Redis/Valkey command analysis for redis-cli and valkey-cli

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};

/// Read-only Redis commands (case-insensitive)
const READ_ONLY_COMMANDS: &[&str] = &[
    // String
    "GET", "MGET", "STRLEN", "GETRANGE", "GETEX",
    // List
    "LLEN", "LRANGE", "LINDEX", "LPOS",
    // Hash
    "HGET", "HGETALL", "HMGET", "HKEYS", "HVALS", "HLEN", "HEXISTS", "HSCAN", "HSTRLEN",
    // Set
    "SCARD", "SMEMBERS", "SISMEMBER", "SMISMEMBER", "SRANDMEMBER", "SSCAN", "SDIFF", "SINTER", "SUNION",
    // Sorted Set
    "ZCARD", "ZRANGE", "ZRANGEBYSCORE", "ZRANGEBYLEX", "ZCOUNT", "ZSCORE", "ZRANK", "ZREVRANK",
    "ZREVRANGE", "ZREVRANGEBYSCORE", "ZLEXCOUNT", "ZMSCORE", "ZSCAN", "ZRANDMEMBER",
    // Key
    "EXISTS", "TYPE", "TTL", "PTTL", "OBJECT", "SCAN", "KEYS", "RANDOMKEY", "DUMP",
    "TOUCH", "EXPIRETIME", "PEXPIRETIME",
    // Server/Info
    "INFO", "DBSIZE", "TIME", "LASTSAVE", "DEBUG", "MEMORY", "CLIENT",
    "CONFIG GET", "SLOWLOG GET", "COMMAND", "COMMAND COUNT", "COMMAND INFO",
    // Stream (read)
    "XLEN", "XRANGE", "XREVRANGE", "XREAD", "XINFO", "XPENDING",
    // Pub/Sub (read)
    "PUBSUB",
    // Geo
    "GEOPOS", "GEODIST", "GEOHASH", "GEORADIUS", "GEORADIUSBYMEMBER", "GEOSEARCH",
    // HyperLogLog (read)
    "PFCOUNT",
    // Cluster (read)
    "CLUSTER INFO", "CLUSTER NODES", "CLUSTER SLOTS", "CLUSTER KEYSLOT",
    // Misc
    "ECHO", "PING", "QUIT",
];

/// Parsed Redis command with command name and arguments
struct RedisCommand {
    /// The Redis command (e.g., "GET", "CONFIG GET")
    command: String,
    /// Number of arguments after the command
    arg_count: usize,
}

/// Extract the Redis command from redis-cli arguments
fn extract_redis_command(cmd: &Command) -> Option<RedisCommand> {
    // Skip options to find the command
    // Common options: -h host, -p port, -n db, -a password, -u uri, --user, --pass, etc.
    let opts_with_args = [
        "-h", "-p", "-n", "-a", "-u", "--user", "--pass", "--askpass",
        "-c", "--cluster", "--tls-ciphers", "--tls-ca-cert", "--tls-cert", "--tls-key",
    ];

    let mut iter = cmd.args.iter().peekable();
    let mut command_parts: Vec<&str> = Vec::new();

    while let Some(arg) = iter.next() {
        // Skip options with arguments
        if opts_with_args.iter().any(|o| arg == *o) {
            iter.next(); // Skip the argument
            continue;
        }
        // Skip boolean flags
        if arg.starts_with('-') {
            continue;
        }
        // This is the Redis command or its arguments
        command_parts.push(arg);
    }

    if command_parts.is_empty() {
        return None;
    }

    // Build command string (first 1-2 parts for compound commands like CONFIG GET)
    let (redis_cmd, arg_count) = if command_parts.len() >= 2 {
        // Check if this is a compound command (like CONFIG GET)
        let potential_compound = format!("{} {}", command_parts[0], command_parts[1]).to_uppercase();
        if READ_ONLY_COMMANDS.iter().any(|c| *c == potential_compound) {
            (potential_compound, command_parts.len() - 2)
        } else {
            (command_parts[0].to_uppercase(), command_parts.len() - 1)
        }
    } else {
        (command_parts[0].to_uppercase(), 0)
    };

    Some(RedisCommand {
        command: redis_cmd,
        arg_count,
    })
}

/// Check if a Redis command is read-only
fn is_read_only(redis_cmd: &str) -> bool {
    let upper = redis_cmd.to_uppercase();

    // Check exact match first (for compound commands like "CONFIG GET")
    if READ_ONLY_COMMANDS.iter().any(|c| upper == *c) {
        return true;
    }

    // Check if first word matches (for simple commands)
    let first_word = upper.split_whitespace().next().unwrap_or("");
    READ_ONLY_COMMANDS.iter().any(|c| *c == first_word)
}

/// Check if a redis-cli or valkey-cli command is read-only
pub fn check_redis_cli(cmd: &Command) -> Option<PermissionResult> {
    if cmd.name != "redis-cli" && cmd.name != "valkey-cli" {
        return None;
    }

    let redis_cmd = extract_redis_command(cmd)?;

    // Extract just the command name (first word) for display
    let cmd_name = redis_cmd
        .command
        .split_whitespace()
        .next()
        .unwrap_or(&redis_cmd.command);

    if is_read_only(&redis_cmd.command) {
        Some(PermissionResult {
            permission: Permission::Allow,
            reason: format!("read-only Redis command: {}", cmd_name),
            suggestion: None,
        })
    } else if redis_cmd.command == "DEL" && redis_cmd.arg_count == 1 {
        // Allow single-key deletes (common cache invalidation)
        Some(PermissionResult {
            permission: Permission::Allow,
            reason: "single-key DEL (cache invalidation)".to_string(),
            suggestion: None,
        })
    } else {
        Some(PermissionResult {
            permission: Permission::Ask,
            reason: format!("Redis write command: {}", cmd_name),
            suggestion: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "redis-cli".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("redis-cli {}", args.join(" ")),
        }
    }

    fn make_valkey_cmd(args: &[&str]) -> Command {
        Command {
            name: "valkey-cli".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("valkey-cli {}", args.join(" ")),
        }
    }

    #[test]
    fn test_llen_allowed() {
        let cmd = make_cmd(&["-n", "1", "llen", "rq:queue:TaskTrackPageView"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
        assert!(result.reason.contains("read-only"), "reason should contain 'read-only': {}", result.reason);
    }

    #[test]
    fn test_get_allowed() {
        let cmd = make_cmd(&["get", "mykey"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_keys_allowed() {
        let cmd = make_cmd(&["keys", "rq:*"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_info_allowed() {
        let cmd = make_cmd(&["info"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_hgetall_allowed() {
        let cmd = make_cmd(&["-h", "localhost", "-p", "6379", "hgetall", "myhash"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_set_asks() {
        let cmd = make_cmd(&["set", "mykey", "myvalue"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_del_single_key_allowed() {
        let cmd = make_cmd(&["del", "mykey"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
        assert!(result.reason.contains("single-key DEL"));
    }

    #[test]
    fn test_del_multi_key_asks() {
        let cmd = make_cmd(&["del", "key1", "key2"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_lpush_asks() {
        let cmd = make_cmd(&["-n", "0", "lpush", "mylist", "value"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_flushdb_asks() {
        let cmd = make_cmd(&["flushdb"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_config_get_allowed() {
        let cmd = make_cmd(&["config", "get", "maxmemory"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_config_set_asks() {
        let cmd = make_cmd(&["config", "set", "maxmemory", "100mb"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_no_command_returns_none() {
        let cmd = make_cmd(&["-h", "localhost"]);
        let result = check_redis_cli(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_zrange_allowed() {
        let cmd = make_cmd(&["zrange", "myset", "0", "-1"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_scan_allowed() {
        let cmd = make_cmd(&["scan", "0", "match", "user:*"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    // Valkey-cli tests (same behavior as redis-cli)

    #[test]
    fn test_valkey_get_allowed() {
        let cmd = make_valkey_cmd(&["get", "mykey"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_valkey_set_asks() {
        let cmd = make_valkey_cmd(&["set", "mykey", "myvalue"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_valkey_info_allowed() {
        let cmd = make_valkey_cmd(&["-h", "localhost", "info"]);
        let result = check_redis_cli(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
