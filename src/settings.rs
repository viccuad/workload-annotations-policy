use std::collections::HashSet;

use criteria_policy_base::{kubewarden_policy_sdk as kubewarden, settings::BaseSettings};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Settings(pub(crate) BaseSettings);

// It's not possible to use the Default in the derive macro because we cannot
// set a #[default] attribute to enum item that is no unit enums.
impl Default for Settings {
    fn default() -> Self {
        Settings(BaseSettings::ContainsAnyOf {
            values: HashSet::new(),
        })
    }
}

// Regex used to validate the annotations name:
// - (Optional) prefix: DNS subdomain (max 253 chars), e.g. `example.com/`
// - Key: can contain alphanumeric characters, dashes, underscores, and dots, max 63 chars.
// with the subdomain `/`escaped for a Rust literal
const ANNOTATIONS_NAME_REGEX: &str = r"^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$";

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        self.0.validate()?;

        let annots = self.0.values();

        // Validate that the annotations names are valid.
        let annotations_name_regex = Regex::new(ANNOTATIONS_NAME_REGEX).unwrap();
        let invalid_annot: Vec<String> = annots
            .iter()
            .filter_map(|annot| {
                if annotations_name_regex.is_match(annot) {
                    return None;
                }
                Some(annot.to_string())
            })
            .collect();
        if !invalid_annot.is_empty() {
            return Err(format!(
                "Invalid annotation names: {}",
                invalid_annot.join(", "),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden::settings::Validatable;
    use rstest::rstest;

    #[rstest]
    #[case::empty_settings(vec![], false)]
    #[case::valid_simple(vec!["my-annotation"], true)]
    #[case::valid_dot(vec!["my.annotation"], true)]
    #[case::valid_underscore(vec!["my_annotation"], true)]
    #[case::valid_dns_prefix(vec!["example.com/my-annotation"], true)]
    #[case::valid_multiple_prefix(vec!["foo.bar.baz/qux"], true)]
    #[case::valid_short(vec!["a/b"], true)]
    #[case::valid_alphanumeric(vec!["abc123"], true)]
    #[case::valid_complex(vec!["abc/def.ghi_jkl-mno"], true)]
    #[case::invalid_leading_slash(vec!["/my-annotation"], false)]
    #[case::invalid_missing_key(vec!["example.com/"], false)]
    #[case::invalid_leading_dash(vec!["-my-annotation"], false)]
    #[case::invalid_prefix_leading_dash(vec!["example.com/-my-annotation"], false)]
    #[case::invalid_trailing_dash(vec!["example.com/my-annotation-"], false)]
    #[case::invalid_space(vec!["example.com/my annotation"], false)]
    #[case::invalid_at_symbol(vec!["example.com/my@annotation"], false)]
    #[case::invalid_uppercase_prefix(vec!["Example.com/my-annotation"], false)]
    #[case::invalid_double_dot_prefix(vec!["example..com/my-annotation"], false)]
    fn test_validation(#[case] variables: Vec<&str>, #[case] is_ok: bool) {
        let settings = Settings(BaseSettings::ContainsAllOf {
            values: variables
                .iter()
                .map(|v| v.to_string())
                .collect::<HashSet<String>>(),
        });
        assert_eq!(settings.validate().is_ok(), is_ok);
    }
}
