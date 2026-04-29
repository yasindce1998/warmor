use std::ffi::CStr;
use std::os::raw::c_char;

// Policy action codes
const ACTION_DENY: i32 = 0;
const ACTION_ALLOW: i32 = 1;
const ACTION_LOG: i32 = 2;

/// Represents a single policy rule
#[repr(C)]
pub struct PolicyRule {
    uid: u32,
    process_pattern: *const c_char,
    action: u8, // 0=deny, 1=allow, 2=log
}

/// Main enforcement function called from Go
/// Returns: 0=deny, 1=allow, 2=log
#[no_mangle]
pub extern "C" fn enforce(
    pid: i32,
    uid: i32,
    process_path: *const c_char,
    rules: *const PolicyRule,
    rule_count: usize,
) -> i32 {
    // Safety checks
    if process_path.is_null() || rules.is_null() {
        return ACTION_DENY; // Deny by default on invalid input
    }

    // Convert C string to Rust string
    let process_str = unsafe {
        match CStr::from_ptr(process_path).to_str() {
            Ok(s) => s,
            Err(_) => return ACTION_DENY, // Invalid UTF-8
        }
    };

    // Convert rules array to slice
    let rules_slice = unsafe { std::slice::from_raw_parts(rules, rule_count) };

    // Evaluate policies in order
    for rule in rules_slice {
        if rule.uid != uid as u32 {
            continue; // UID doesn't match, skip this rule
        }

        // Get pattern string
        let pattern = unsafe {
            match CStr::from_ptr(rule.process_pattern).to_str() {
                Ok(s) => s,
                Err(_) => continue, // Skip invalid patterns
            }
        };

        // Check if process matches pattern
        if matches_pattern(process_str, pattern) {
            return rule.action as i32;
        }
    }

    // Default: allow if no matching rule found
    ACTION_ALLOW
}

/// Pattern matching with wildcard support
/// Supports: exact match, prefix match with *, suffix match with *
fn matches_pattern(process: &str, pattern: &str) -> bool {
    if pattern == process {
        return true; // Exact match
    }

    if pattern.contains('*') {
        // Wildcard matching
        if pattern.starts_with('*') && pattern.ends_with('*') {
            // *substring* - contains
            let substring = &pattern[1..pattern.len() - 1];
            return process.contains(substring);
        } else if pattern.starts_with('*') {
            // *suffix - ends with
            let suffix = &pattern[1..];
            return process.ends_with(suffix);
        } else if pattern.ends_with('*') {
            // prefix* - starts with
            let prefix = &pattern[..pattern.len() - 1];
            return process.starts_with(prefix);
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(matches_pattern("/bin/bash", "/bin/bash"));
        assert!(!matches_pattern("/bin/bash", "/bin/sh"));
    }

    #[test]
    fn test_prefix_wildcard() {
        assert!(matches_pattern("/tmp/go-build123", "/tmp/go-build*"));
        assert!(matches_pattern("/tmp/go-build", "/tmp/go-build*"));
        assert!(!matches_pattern("/tmp/other", "/tmp/go-build*"));
    }

    #[test]
    fn test_suffix_wildcard() {
        assert!(matches_pattern("/usr/bin/bash", "*/bash"));
        assert!(!matches_pattern("/usr/bin/sh", "*/bash"));
    }

    #[test]
    fn test_contains_wildcard() {
        assert!(matches_pattern("/usr/local/bin/node", "*local*"));
        assert!(!matches_pattern("/usr/bin/node", "*local*"));
    }
}
