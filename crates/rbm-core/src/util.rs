use serde::Serialize;

/// Result of integer base conversion.
#[derive(Serialize, Debug)]
pub struct IntConvertResult {
    pub input: String,
    pub decimal: String,
    pub hex: String,
    pub binary: String,
    pub octal: String,
    pub ascii: Option<String>,
}

/// Parse a string as an integer in any common base: decimal, hex (0x), binary (0b), octal (0o).
///
/// # Errors
///
/// Returns an error if the input is empty or cannot be parsed in a supported base.
pub fn int_convert(value: &str) -> Result<IntConvertResult, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("empty input".into());
    }

    let n: u64 = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex: {e}"))?
    } else if let Some(bin) = trimmed
        .strip_prefix("0b")
        .or_else(|| trimmed.strip_prefix("0B"))
    {
        u64::from_str_radix(bin, 2).map_err(|e| format!("invalid binary: {e}"))?
    } else if let Some(oct) = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
    {
        u64::from_str_radix(oct, 8).map_err(|e| format!("invalid octal: {e}"))?
    } else if trimmed.chars().all(|c| c.is_ascii_digit()) {
        trimmed
            .parse::<u64>()
            .map_err(|e| format!("invalid decimal: {e}"))?
    } else {
        return Err(format!(
            "unrecognised numeric format: {trimmed} (use 123, 0x1a, 0b1010, or 0o755)"
        ));
    };

    let ascii = printable_ascii_bytes(n);

    Ok(IntConvertResult {
        input: trimmed.to_string(),
        decimal: n.to_string(),
        hex: format!("0x{n:x}"),
        binary: format!("0b{n:b}"),
        octal: format!("0o{n:o}"),
        ascii,
    })
}

/// If all non-zero bytes are printable ASCII, return them as a string.
fn printable_ascii_bytes(n: u64) -> Option<String> {
    if n == 0 {
        return None;
    }
    let bytes = n.to_be_bytes();
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let usable = &bytes[leading_zeros..];
    if usable.is_empty() {
        return None;
    }
    if usable
        .iter()
        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        Some(usable.iter().map(|&b| b as char).collect())
    } else {
        None
    }
}
