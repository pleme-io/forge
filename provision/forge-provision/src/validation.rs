//! Security validation utilities for database provisioning
//!
//! This module provides defense-in-depth validation for PostgreSQL identifiers
//! and credentials to prevent SQL injection and other security issues.

use anyhow::Result;

/// Maximum length for PostgreSQL identifiers (standard limit)
pub const PG_IDENTIFIER_MAX_LENGTH: usize = 63;

/// Characters allowed in PostgreSQL identifiers (alphanumeric, underscore, dollar)
const IDENTIFIER_ALLOWED_CHARS: &[char] = &['_', '$'];

/// Characters allowed in PostgreSQL extension names (alphanumeric, underscore, hyphen)
const EXTENSION_ALLOWED_CHARS: &[char] = &['_', '-'];

/// Validate PostgreSQL identifier to prevent SQL injection
///
/// PostgreSQL identifiers must:
/// - Not be empty
/// - Not exceed 63 characters
/// - Start with a letter or underscore
/// - Contain only alphanumeric, underscore, or dollar sign
///
/// # Arguments
/// * `name` - The identifier to validate
/// * `field_name` - Description of the field for error messages
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(anyhow::Error)` with detailed message if invalid
pub fn validate_pg_identifier(name: &str, field_name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("{} cannot be empty", field_name);
    }

    if name.len() > PG_IDENTIFIER_MAX_LENGTH {
        anyhow::bail!(
            "{} exceeds PostgreSQL maximum identifier length ({} > {})",
            field_name,
            name.len(),
            PG_IDENTIFIER_MAX_LENGTH
        );
    }

    // Must start with letter or underscore
    // Safety: we've already validated the string is non-empty above
    let first_char = name.chars().next().unwrap();

    if !first_char.is_ascii_alphabetic() && first_char != '_' {
        anyhow::bail!(
            "{} must start with a letter or underscore, got: '{}'",
            field_name,
            first_char
        );
    }

    // Must contain only alphanumeric, underscore, or dollar sign
    let invalid_chars: Vec<char> = name
        .chars()
        .filter(|c| !c.is_ascii_alphanumeric() && !IDENTIFIER_ALLOWED_CHARS.contains(c))
        .collect();

    if !invalid_chars.is_empty() {
        anyhow::bail!(
            "{} contains invalid characters: {:?} (allowed: a-z, A-Z, 0-9, _, $)",
            field_name,
            invalid_chars
        );
    }

    Ok(())
}

/// Validate PostgreSQL extension name
///
/// PostgreSQL extension names have slightly different rules than identifiers:
/// - They can contain hyphens (e.g., "uuid-ossp", "pg-trgm")
/// - They must still be safe from SQL injection
///
/// # Arguments
/// * `name` - The extension name to validate
/// * `field_name` - Description of the field for error messages
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(anyhow::Error)` with detailed message if invalid
pub fn validate_pg_extension_name(name: &str, field_name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("{} cannot be empty", field_name);
    }

    if name.len() > PG_IDENTIFIER_MAX_LENGTH {
        anyhow::bail!(
            "{} exceeds PostgreSQL maximum identifier length ({} > {})",
            field_name,
            name.len(),
            PG_IDENTIFIER_MAX_LENGTH
        );
    }

    // Extension names should contain only alphanumeric, underscore, or hyphen
    let invalid_chars: Vec<char> = name
        .chars()
        .filter(|c| !c.is_ascii_alphanumeric() && !EXTENSION_ALLOWED_CHARS.contains(c))
        .collect();

    if !invalid_chars.is_empty() {
        anyhow::bail!(
            "{} contains invalid characters: {:?} (allowed: a-z, A-Z, 0-9, _, -)",
            field_name,
            invalid_chars
        );
    }

    Ok(())
}

/// Quote PostgreSQL identifier for safe SQL interpolation
///
/// Even with validation, we use double-quote escaping for defense in depth.
/// This escapes any double quotes by doubling them, then wraps in double quotes.
///
/// # Arguments
/// * `name` - The identifier to quote
///
/// # Returns
/// Properly quoted identifier safe for SQL interpolation
///
/// # Examples
/// ```
/// use forge_provision::validation::quote_identifier;
///
/// assert_eq!(quote_identifier("users"), "\"users\"");
/// assert_eq!(quote_identifier("my\"table"), "\"my\"\"table\"");
/// ```
pub fn quote_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Validate that a password is not empty and contains no problematic whitespace
///
/// # Arguments
/// * `password` - The password to validate
/// * `field_name` - Description of the field for error messages
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(anyhow::Error)` if empty or contains leading/trailing whitespace
pub fn validate_password(password: &str, field_name: &str) -> Result<()> {
    if password.is_empty() {
        anyhow::bail!("{} cannot be empty", field_name);
    }

    // Warn about leading/trailing whitespace (common mistake)
    if password != password.trim() {
        anyhow::bail!(
            "{} contains leading or trailing whitespace (this is likely unintentional)",
            field_name
        );
    }

    Ok(())
}

/// Validate configuration numeric values are within reasonable bounds
///
/// # Arguments
/// * `value` - The value to validate
/// * `field_name` - Description of the field for error messages
/// * `min` - Minimum allowed value
/// * `max` - Maximum allowed value
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(anyhow::Error)` if out of bounds
pub fn validate_numeric_range(
    value: u64,
    field_name: &str,
    min: u64,
    max: u64,
) -> Result<()> {
    if value < min || value > max {
        anyhow::bail!(
            "{} must be between {} and {}, got: {}",
            field_name,
            min,
            max,
            value
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_identifier_valid() {
        assert!(validate_pg_identifier("users", "table").is_ok());
        assert!(validate_pg_identifier("_private", "column").is_ok());
        assert!(validate_pg_identifier("user_123", "field").is_ok());
        assert!(validate_pg_identifier("price$", "field").is_ok());
    }

    #[test]
    fn test_validate_identifier_invalid() {
        // Empty
        assert!(validate_pg_identifier("", "field").is_err());

        // Starts with number
        assert!(validate_pg_identifier("123user", "field").is_err());

        // Contains invalid chars
        assert!(validate_pg_identifier("user-name", "field").is_err());
        assert!(validate_pg_identifier("user name", "field").is_err());
        assert!(validate_pg_identifier("user@name", "field").is_err());

        // Too long
        let long_name = "a".repeat(64);
        assert!(validate_pg_identifier(&long_name, "field").is_err());
    }

    #[test]
    fn test_quote_identifier() {
        assert_eq!(quote_identifier("users"), "\"users\"");
        assert_eq!(quote_identifier("my\"table"), "\"my\"\"table\"");
        assert_eq!(quote_identifier("a\"b\"c"), "\"a\"\"b\"\"c\"");
    }

    #[test]
    fn test_validate_password() {
        // Valid passwords
        assert!(validate_password("secret123", "password").is_ok());
        assert!(validate_password("c0mpl3x!P@ssw0rd", "password").is_ok());
        assert!(validate_password("with spaces inside", "password").is_ok());

        // Invalid passwords
        assert!(validate_password("", "password").is_err());
        assert!(validate_password(" leading_space", "password").is_err());
        assert!(validate_password("trailing_space ", "password").is_err());
        assert!(validate_password(" both ", "password").is_err());
    }

    #[test]
    fn test_validate_numeric_range() {
        // Valid values
        assert!(validate_numeric_range(5, "port", 1, 10).is_ok());
        assert!(validate_numeric_range(1, "port", 1, 10).is_ok());
        assert!(validate_numeric_range(10, "port", 1, 10).is_ok());

        // Invalid values
        assert!(validate_numeric_range(0, "port", 1, 10).is_err());
        assert!(validate_numeric_range(11, "port", 1, 10).is_err());
        assert!(validate_numeric_range(100, "port", 1, 10).is_err());
    }

    #[test]
    fn test_validate_extension_name_valid() {
        // Common PostgreSQL extensions with hyphens
        assert!(validate_pg_extension_name("uuid-ossp", "extension").is_ok());
        assert!(validate_pg_extension_name("pg-trgm", "extension").is_ok());
        assert!(validate_pg_extension_name("pg_stat_statements", "extension").is_ok());
        assert!(validate_pg_extension_name("hstore", "extension").is_ok());
    }

    #[test]
    fn test_validate_extension_name_invalid() {
        // Empty
        assert!(validate_pg_extension_name("", "extension").is_err());

        // Contains invalid chars
        assert!(validate_pg_extension_name("ext name", "extension").is_err());
        assert!(validate_pg_extension_name("ext@name", "extension").is_err());
        assert!(validate_pg_extension_name("ext/name", "extension").is_err());

        // Too long
        let long_name = "a".repeat(64);
        assert!(validate_pg_extension_name(&long_name, "extension").is_err());
    }
}
