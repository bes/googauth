use super::ConfigName;
use crate::errors::LibError;
use std::str::FromStr;

#[test]
fn accepts_file_names() {
    for name in [
        "work",
        "work-2",
        "work_2",
        "work.prod",
        ".hidden",
        "my work",
        "...",
    ] {
        assert_eq!(ConfigName::from_str(name).unwrap().as_str(), name);
    }
}

#[test]
fn rejects_names_that_are_not_file_names() {
    for name in [
        "",
        ".",
        "..",
        "../work",
        "./work",
        "/work",
        "/",
        "work/",
        "work/.",
        "work/..",
        "nested/work",
        "work\0",
    ] {
        assert!(
            matches!(
                ConfigName::from_str(name),
                Err(LibError::InvalidConfigName(rejected)) if rejected == name
            ),
            "{name:?}"
        );
    }
}

#[test]
fn is_stored_as_a_json_string() {
    let name = ConfigName::from_str("work").unwrap();

    assert_eq!(serde_json::to_string(&name).unwrap(), r#""work""#);
    assert_eq!(
        serde_json::from_str::<ConfigName>(r#""work""#).unwrap(),
        name
    );
    assert!(serde_json::from_str::<ConfigName>(r#""../work""#).is_err());
}

#[test]
fn display_honors_padding() {
    let name = ConfigName::from_str("work").unwrap();

    assert_eq!(format!("{name: <8}|"), "work    |");
}
