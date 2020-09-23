use crate::ServiceError;

use derive_more::{Display, From};
use muta_codec_derive::RlpFixedCodec;
use protocol::{
    fixed_codec::{FixedCodec, FixedCodecError},
    types::Address,
    Bytes, ProtocolResult,
};
use serde::de::{Deserializer, Error, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::expression::{
    validate_org_name, validate_tag_name, validate_tag_value, validate_tag_values_update,
    ExpressionError,
};
use std::str::FromStr;
use std::{
    collections::HashMap,
    fmt,
    ops::{Deref, DerefMut},
};

const ORG_DESCRIPTION_LENGTH: usize = 256usize;

pub trait Validate {
    fn validate(&self) -> Result<(), ServiceError>;
}

pub trait ValidateBase {
    fn validate(&self) -> Result<(), ExpressionError>;
}

#[derive(Debug, From, Display)]
#[display(fmt = "{}", _0)]
pub struct BadPayload(&'static str);

impl From<BadPayload> for ServiceError {
    fn from(err: BadPayload) -> ServiceError {
        ServiceError::BadPayload(err.0.to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Display)]
#[display(fmt = "{}", _0)]
pub struct TagName(pub String);

impl TagName {
    pub fn new(s: String) -> Self {
        TagName(s)
    }
}

impl FromStr for TagName {
    type Err = ServiceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tag_name = TagName::new(s.to_owned());
        tag_name.validate().map_err(ServiceError::from)?;
        Ok(tag_name)
    }
}

impl ValidateBase for TagName {
    fn validate(&self) -> Result<(), ExpressionError> {
        validate_tag_name(self.0.clone())?;
        Ok(())
    }
}

impl rlp::Encodable for TagName {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        self.0.rlp_append(s)
    }
}

impl rlp::Decodable for TagName {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let name = String::decode(rlp)?;
        let ret = TagName::new(name);
        ret.validate()
            .map_err(|e| rlp::DecoderError::Custom(e.as_str()))?;

        Ok(ret)
    }
}

impl FixedCodec for TagName {
    fn encode_fixed(&self) -> ProtocolResult<Bytes> {
        Ok(rlp::encode(self).into())
    }

    fn decode_fixed(bytes: Bytes) -> ProtocolResult<Self> {
        Ok(rlp::decode(&bytes).map_err(FixedCodecError::from)?)
    }
}

impl<'de> Deserialize<'de> for TagName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVisitor;

        impl<'de> Visitor<'de> for StringVisitor {
            type Value = TagName;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("tag name serializing fails")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let ret = TagName::new(v.to_string());
                ret.validate().map_err(serde::de::Error::custom)?;
                Ok(ret)
            }
        }

        deserializer.deserialize_str(StringVisitor)
    }
}

impl Deref for TagName {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TagName {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Into<String> for TagName {
    fn into(self) -> String {
        self.0
    }
}

//===========================
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Display)]
#[display(fmt = "{}", _0)]
pub struct TagValue(pub String);

impl TagValue {
    pub fn new(s: String) -> Self {
        TagValue(s)
    }
}

impl FromStr for TagValue {
    type Err = ServiceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tag_value = TagValue::new(s.to_owned());
        tag_value.validate().map_err(ServiceError::from)?;
        Ok(tag_value)
    }
}

impl ValidateBase for TagValue {
    fn validate(&self) -> Result<(), ExpressionError> {
        validate_tag_value(self.0.clone())?;
        Ok(())
    }
}

impl rlp::Encodable for TagValue {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        self.0.rlp_append(s)
    }
}

impl rlp::Decodable for TagValue {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let name = String::decode(rlp)?;
        let ret = TagValue::new(name);
        ret.validate()
            .map_err(|e| rlp::DecoderError::Custom(e.as_str()))?;

        Ok(ret)
    }
}

impl FixedCodec for TagValue {
    fn encode_fixed(&self) -> ProtocolResult<Bytes> {
        Ok(rlp::encode(self).into())
    }

    fn decode_fixed(bytes: Bytes) -> ProtocolResult<Self> {
        Ok(rlp::decode(&bytes).map_err(FixedCodecError::from)?)
    }
}

impl<'de> Deserialize<'de> for TagValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVisitor;

        impl<'de> Visitor<'de> for StringVisitor {
            type Value = TagValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("tag value serializing fails")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let ret = TagValue::new(v.to_string());
                ret.validate().map_err(serde::de::Error::custom)?;
                Ok(ret)
            }
        }

        deserializer.deserialize_str(StringVisitor)
    }
}

impl Deref for TagValue {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TagValue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Into<String> for TagValue {
    fn into(self) -> String {
        self.0
    }
}

//===========================

#[derive(Debug, Serialize, PartialEq, Eq, Hash, Clone, Display)]
#[display(fmt = "{}", _0)]
pub struct OrgName(pub String);

impl OrgName {
    pub fn new(s: String) -> Self {
        OrgName(s)
    }
}

impl FromStr for OrgName {
    type Err = ServiceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let org_name = OrgName::new(s.to_owned());
        org_name.validate().map_err(ServiceError::from)?;
        Ok(org_name)
    }
}

impl ValidateBase for OrgName {
    fn validate(&self) -> Result<(), ExpressionError> {
        validate_org_name(self.0.clone())?;
        Ok(())
    }
}

impl rlp::Encodable for OrgName {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        self.0.rlp_append(s)
    }
}

impl rlp::Decodable for OrgName {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let name = String::decode(rlp)?;
        let ret = OrgName::new(name);
        ret.validate()
            .map_err(|e| rlp::DecoderError::Custom(e.as_str()))?;

        Ok(ret)
    }
}

impl FixedCodec for OrgName {
    fn encode_fixed(&self) -> ProtocolResult<Bytes> {
        Ok(rlp::encode(self).into())
    }

    fn decode_fixed(bytes: Bytes) -> ProtocolResult<Self> {
        Ok(rlp::decode(&bytes).map_err(FixedCodecError::from)?)
    }
}

impl Deref for OrgName {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for OrgName {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'de> Deserialize<'de> for OrgName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVisitor;

        impl<'de> Visitor<'de> for StringVisitor {
            type Value = OrgName;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("org name serializing fails")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let ret = OrgName::new(v.to_string());
                ret.validate().map_err(serde::de::Error::custom)?;
                Ok(ret)
            }
        }

        deserializer.deserialize_str(StringVisitor)
    }
}

//===========================

#[derive(Debug, Serialize, Deserialize)]
pub struct Genesis {
    pub org_name:        OrgName,
    pub org_description: String,
    pub org_admin:       Address,
    pub supported_tags:  Vec<TagName>,
    pub service_admin:   Address,
}

impl Validate for Genesis {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.org_description.len() >= ORG_DESCRIPTION_LENGTH {
            return Err(BadPayload("description length exceed ").into());
        }

        if self.org_admin == Address::default() {
            return Err(BadPayload("invalid org admin address").into());
        }

        if self.service_admin == Address::default() {
            return Err(BadPayload("invalid service admin address").into());
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, RlpFixedCodec)]
pub struct KycOrgInfo {
    pub name:           OrgName,
    pub description:    String,
    pub admin:          Address,
    pub supported_tags: Vec<TagName>,
    pub approved:       bool,
}

impl Validate for KycOrgInfo {
    // Note: TagName and OrgName is already validated during deserialization,
    // and there's not way to create invalid TagName from public function.
    fn validate(&self) -> Result<(), ServiceError> {
        if self.description.len() >= ORG_DESCRIPTION_LENGTH {
            return Err(BadPayload("description length exceed").into());
        }

        if self.admin == Address::default() {
            return Err(BadPayload("invalid org admin address").into());
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct FixedTagList(pub Vec<TagValue>);

impl FixedTagList {
    pub fn new(values: Vec<String>) -> Self {
        let tag_values = values.into_iter().map(TagValue::new).collect::<Vec<_>>();
        FixedTagList(tag_values)
    }

    pub fn validate_new(values: Vec<String>) -> Result<Self, ServiceError> {
        let ret = Self::new(values);
        ret.validate().map_err(ServiceError::from)?;
        Ok(ret)
    }

    pub fn validate_new_tag_value(values: Vec<TagValue>) -> Result<Self, ServiceError> {
        let ret = FixedTagList(values);
        ret.validate().map_err(ServiceError::from)?;
        Ok(ret)
    }
}

impl ValidateBase for FixedTagList {
    fn validate(&self) -> Result<(), ExpressionError> {
        let values = self
            .0
            .iter()
            .map(|tag_value| tag_value.0.clone())
            .collect::<Vec<_>>();
        validate_tag_values_update(values)?;
        Ok(())
    }
}

impl Into<Vec<String>> for FixedTagList {
    fn into(self) -> Vec<String> {
        self.0.into_iter().map(Into::into).collect()
    }
}

impl Deref for FixedTagList {
    type Target = Vec<TagValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FixedTagList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl IntoIterator for FixedTagList {
    type IntoIter = std::vec::IntoIter<Self::Item>;
    type Item = TagValue;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FixedCodec for FixedTagList {
    fn encode_fixed(&self) -> ProtocolResult<Bytes> {
        Ok(rlp::encode_list(self).into())
    }

    fn decode_fixed(bytes: Bytes) -> ProtocolResult<Self> {
        let rlp = rlp::Rlp::new(&bytes);
        let tag_values = rlp.as_list().map_err(FixedCodecError::from)?;

        let ret = FixedTagList::new(tag_values);
        ret.validate()
            .map_err(|e| rlp::DecoderError::Custom(e.as_str()))
            .map_err(FixedCodecError::from)?;

        Ok(ret)
    }
}

impl<'de> Deserialize<'de> for FixedTagList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagValuesVisitor;

        impl<'de> Visitor<'de> for TagValuesVisitor {
            type Value = FixedTagList;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("FixedTagList serialization fails")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut vec = Vec::new();

                while let Some(elem) = seq.next_element::<Option<TagValue>>()? {
                    vec.extend(elem.map(|tag_value| tag_value.0));
                }

                let ret = FixedTagList::new(vec);
                ret.validate().map_err(A::Error::custom)?;
                Ok(ret)
            }
        }

        deserializer.deserialize_seq(TagValuesVisitor)
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct KycUserInfo {
    pub tags: HashMap<TagName, FixedTagList>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangeOrgApproved {
    pub org_name: OrgName,
    pub approved: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisterNewOrg {
    pub name:           OrgName,
    pub description:    String,
    pub admin:          Address,
    pub supported_tags: Vec<TagName>,
}

impl Validate for RegisterNewOrg {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.description.len() >= ORG_DESCRIPTION_LENGTH {
            return Err(BadPayload("description length exceed").into());
        }

        if self.admin == Address::default() {
            return Err(BadPayload("invalid admin address").into());
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewOrgEvent {
    pub name:           OrgName,
    pub supported_tags: Vec<TagName>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct UpdateOrgSupportTags {
    pub org_name:       OrgName,
    pub supported_tags: Vec<TagName>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct UpdateUserTags {
    pub org_name: OrgName,
    pub user:     Address,
    pub tags:     HashMap<TagName, FixedTagList>,
}

impl Validate for UpdateUserTags {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.user == Address::default() {
            return Err(BadPayload("invalid user address").into());
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserTags {
    pub org_name: OrgName,
    pub user:     Address,
}

impl Validate for GetUserTags {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.user == Address::default() {
            Err(BadPayload("invalid user address").into())
        } else {
            Ok(())
        }
    }
}
#[derive(Debug, Deserialize)]
pub struct EvalUserTagExpression {
    pub user:       Address,
    pub expression: String,
}

impl Validate for EvalUserTagExpression {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.user == Address::default() {
            Err(BadPayload("invalid user address").into())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangeOrgAdmin {
    pub name:      OrgName,
    pub new_admin: Address,
}

impl Validate for ChangeOrgAdmin {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.new_admin == Address::default() {
            Err(BadPayload("invalid admin address").into())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangeServiceAdmin {
    pub new_admin: Address,
}

impl Validate for ChangeServiceAdmin {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.new_admin == Address::default() {
            Err(BadPayload("invalid admin address").into())
        } else {
            Ok(())
        }
    }
}
