use crate::errors::LibError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Component, Path};
use std::str::FromStr;

#[cfg(test)]
mod tests;

/// A configuration name is always a plain file name, so that a configuration can only ever be read
/// from or saved to its own file in the configuration directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ConfigName(String);

impl ConfigName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ConfigName {
    type Error = LibError;

    fn try_from(name: String) -> Result<ConfigName, LibError> {
        if is_plain_file_name(&name) {
            Ok(ConfigName(name))
        } else {
            Err(LibError::InvalidConfigName(name))
        }
    }
}

impl FromStr for ConfigName {
    type Err = LibError;

    fn from_str(name: &str) -> Result<ConfigName, LibError> {
        ConfigName::try_from(name.to_string())
    }
}

impl From<ConfigName> for String {
    fn from(name: ConfigName) -> String {
        name.0
    }
}

impl fmt::Display for ConfigName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

fn is_plain_file_name(name: &str) -> bool {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(file_name)), None) => file_name == name && !name.contains('\0'),
        _ => false,
    }
}
