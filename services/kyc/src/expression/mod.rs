mod evaluation;
mod node;
mod token;
pub mod traits;
pub mod types;

#[cfg(test)]
pub mod tests;

use derive_more::Display;
use protocol::types::Address;

use crate::expression::traits::ExpressionDataFeed;
use node::parse;
use token::scan;
use types::CalcContext;

pub const ORG_NAME_LENGTH: usize = 32usize;
pub const TAG_NAME_LENGTH: usize = 32usize;
pub const TAG_VALUE_LENGTH: usize = 32usize;
pub const TAG_VALUE_CAPACITY: usize = 16usize;

#[derive(Debug, Display, PartialEq)]
pub enum ExpressionError {
    #[display(fmt = "scan token: {}", _0)]
    Scan(&'static str),

    #[display(fmt = "parse node: {}", _0)]
    Parse(&'static str),

    #[display(fmt = "calculate node: {}", _0)]
    Calculate(&'static str),

    #[display(fmt = "validate: {}", _0)]
    Validate(&'static str),
}

impl ExpressionError {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExpressionError::Scan(str) => str,
            ExpressionError::Parse(str) => str,
            ExpressionError::Calculate(str) => str,
            ExpressionError::Validate(str) => str,
        }
    }
}

pub type ExpressionResult = Result<bool, ExpressionError>;

pub fn evaluate<DF: ExpressionDataFeed>(
    data_feeder: &DF,
    target_address: Address,
    expr: String,
) -> ExpressionResult {
    let tokens = scan(expr)?;
    let node = parse(tokens)?;
    let calc_context = CalcContext::new(data_feeder, target_address);
    calc_context.calculation(&node)
}

// org name, tag name, tag value can be customized individually

// s.t. regexp /^[a-zA-Z][a-zA-Z\d_]{0,31}}/
pub fn validate_org_name(ident: String) -> Result<(), ExpressionError> {
    if ident.chars().count() > ORG_NAME_LENGTH || ident.chars().count() == 0 {
        return Err(ExpressionError::Validate("org name length exceed"));
    }
    for (index, char) in ident.chars().enumerate() {
        if !(char.is_ascii_alphanumeric() || char == '_') {
            return Err(ExpressionError::Validate(
                "org name only support ascii alpha, number, underscore",
            ));
        }
        if index == 0 && !char.is_ascii_alphabetic() {
            return Err(ExpressionError::Validate(
                "org name must start with alpha latter",
            ));
        }
    }
    Ok(())
}

// s.t. regexp /^[a-zA-Z][a-zA-Z\d_]{0,31}}/
pub fn validate_tag_name(ident: String) -> Result<(), ExpressionError> {
    if ident.chars().count() > TAG_NAME_LENGTH || ident.chars().count() == 0 {
        return Err(ExpressionError::Validate("tag name length exceed"));
    }
    for (index, char) in ident.chars().enumerate() {
        if !(char.is_ascii_alphanumeric() || char == '_') {
            return Err(ExpressionError::Validate(
                "tag name only support ascii alpha, number, underscore",
            ));
        }
        if index == 0 && !char.is_ascii_alphabetic() {
            return Err(ExpressionError::Validate(
                "tag name must start with alpha latter",
            ));
        }
    }
    Ok(())
}

// s.t. regexp /^[a-zA-Z][a-zA-Z\d_]{0,31}}/
pub fn validate_tag_value(ident: String) -> Result<(), ExpressionError> {
    if ident.chars().count() > TAG_VALUE_LENGTH || ident.chars().count() == 0 {
        return Err(ExpressionError::Validate("tag value length exceed"));
    }
    for (index, char) in ident.chars().enumerate() {
        if !(char.is_ascii_alphanumeric() || char == '_') {
            return Err(ExpressionError::Validate(
                "tag value only support ascii alpha, number, underscore",
            ));
        }
        if index == 0 && !char.is_ascii_alphabetic() {
            return Err(ExpressionError::Validate(
                "tag value must start with alpha latter",
            ));
        }
    }
    Ok(())
}

// len between 1 to 16
// if there is NULL, the values can't contain any other values
pub fn validate_tag_values_query(tag_values: Vec<String>) -> Result<(), ExpressionError> {
    let len = tag_values.len();

    if len == 0 || len > TAG_VALUE_CAPACITY {
        return Err(ExpressionError::Validate(
            "tag values length is zero, or tag values length exceed capacity",
        ));
    }

    for value in tag_values {
        validate_tag_value(value.clone())?;

        if value.eq("NULL") && len != 1 {
            return Err(ExpressionError::Validate(
                "tag value query contains 'NULL', but also contains other values",
            ));
        }
    }

    Ok(())
}

pub fn validate_tag_values_update(tag_values: Vec<String>) -> Result<(), ExpressionError> {
    let len = tag_values.len();

    if len == 0 || len > TAG_VALUE_CAPACITY {
        return Err(ExpressionError::Validate(
            "tag values length is zero, or tag values length exceed capacity",
        ));
    }

    for value in tag_values {
        validate_tag_value(value.clone())?;

        if value.eq("NULL") {
            return Err(ExpressionError::Validate(
                "tag value update contains 'NULL', which is a reserved key work",
            ));
        }
    }

    Ok(())
}
