use rbm_core::int_convert;

#[test]
fn util_int_convert_decimal() {
    let result = int_convert("42").unwrap();
    assert_eq!(result.decimal, "42");
    assert_eq!(result.hex, "0x2a");
    assert_eq!(result.binary, "0b101010");
    assert_eq!(result.octal, "0o52");
}

#[test]
fn util_int_convert_hex() {
    let result = int_convert("0xff").unwrap();
    assert_eq!(result.decimal, "255");
    assert_eq!(result.hex, "0xff");
}

#[test]
fn util_int_convert_binary() {
    let result = int_convert("0b1101").unwrap();
    assert_eq!(result.decimal, "13");
}

#[test]
fn util_int_convert_octal() {
    let result = int_convert("0o777").unwrap();
    assert_eq!(result.decimal, "511");
}

#[test]
fn util_int_convert_empty() {
    assert!(int_convert("").is_err());
}

#[test]
fn util_int_convert_ascii() {
    let result = int_convert("0x48656c6c6f").unwrap();
    assert_eq!(result.ascii, Some("Hello".to_string()));
}
