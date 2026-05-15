use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Classification of how an enclave app delivers secrets to the target application.
///
/// The adapter selects the least-secret-exposing integration automatically:
/// `HelperTool` > `EnvInterpolation` > `TempMaterializedConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrationType {
    /// Type 1: The target app calls back to get credentials on demand.
    /// Secrets never leave the enclave app's process boundary.
    /// Examples: SSH agent protocol, AWS `credential_process`, git credential helpers.
    HelperTool,
    /// Type 2: Config file with `${ENV_VAR}` placeholders + secret env vars via `execve()`.
    /// Secrets exist briefly as environment variables but never touch disk.
    /// Examples: npm `.npmrc` with `${NPM_TOKEN}` interpolation.
    EnvInterpolation,
    /// Type 3: Secrets written to a temp file (0o600 permissions), path passed via flag/env var.
    /// Least secure — secrets briefly exist on disk. File deleted after process exits.
    /// Used when the target app has no plugin or env var interpolation support.
    TempMaterializedConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BindingId(String);

impl BindingId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for BindingId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for BindingId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn binding_id_new_stores_and_as_str_returns_same_string() {
        let id = BindingId::new("npm:default");
        assert_eq!(id.as_str(), "npm:default");
    }

    #[test]
    fn binding_id_from_str_ref_produces_equal_value() {
        let a = BindingId::new("x");
        let b = BindingId::from("x");
        assert_eq!(a, b);
    }

    #[test]
    fn binding_id_from_string_produces_equal_value() {
        let a = BindingId::new("x");
        let b = BindingId::from("x".to_string());
        assert_eq!(a, b);
    }

    #[test]
    fn binding_id_from_str_and_from_string_are_equal() {
        let via_str: BindingId = "npm:test".into();
        let via_string: BindingId = "npm:test".to_string().into();
        assert_eq!(via_str, via_string);
    }

    #[test]
    fn binding_id_empty_string() {
        let id = BindingId::new("");
        assert_eq!(id.as_str(), "");
    }

    #[test]
    fn binding_id_clone_is_equal() {
        let a = BindingId::new("npm:default");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn binding_id_ord_lexicographic() {
        let a = BindingId::new("a");
        let b = BindingId::new("b");
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn binding_id_serde_json_roundtrip() {
        let id = BindingId::new("npm:production");
        let json = serde_json::to_string(&id).unwrap();
        let parsed: BindingId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn binding_id_serde_json_serializes_as_plain_string() {
        let id = BindingId::new("test-id");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"test-id\"");
    }

    #[test]
    fn binding_id_debug_format_contains_value() {
        let id = BindingId::new("debug-test");
        let s = format!("{:?}", id);
        assert!(s.contains("debug-test"));
    }

    #[test]
    fn integration_type_serde_roundtrip_all_variants() {
        for variant in [
            IntegrationType::HelperTool,
            IntegrationType::EnvInterpolation,
            IntegrationType::TempMaterializedConfig,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: IntegrationType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn binding_record_serde_roundtrip() {
        let record = BindingRecord {
            id: BindingId::new("npm:default"),
            label: "label".into(),
            target: "target-app".into(),
            secret_env_var: "NPM_TOKEN".into(),
            metadata: [("key".into(), "val".into())].into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: BindingRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn integration_type_all_variants_equal_to_themselves() {
        assert_eq!(IntegrationType::HelperTool, IntegrationType::HelperTool);
        assert_eq!(
            IntegrationType::EnvInterpolation,
            IntegrationType::EnvInterpolation
        );
        assert_eq!(
            IntegrationType::TempMaterializedConfig,
            IntegrationType::TempMaterializedConfig
        );
    }

    #[test]
    fn integration_type_all_variants_not_equal_to_others() {
        assert_ne!(
            IntegrationType::HelperTool,
            IntegrationType::EnvInterpolation
        );
        assert_ne!(
            IntegrationType::HelperTool,
            IntegrationType::TempMaterializedConfig
        );
        assert_ne!(
            IntegrationType::EnvInterpolation,
            IntegrationType::TempMaterializedConfig
        );
    }

    #[test]
    fn integration_type_debug_format_nonempty() {
        for variant in [
            IntegrationType::HelperTool,
            IntegrationType::EnvInterpolation,
            IntegrationType::TempMaterializedConfig,
        ] {
            assert!(!format!("{variant:?}").is_empty());
        }
    }

    #[test]
    fn resolution_strategy_all_variants_equal_to_themselves() {
        assert_eq!(
            ResolutionStrategy::ExplicitPath,
            ResolutionStrategy::ExplicitPath
        );
        assert_eq!(
            ResolutionStrategy::PathLookup,
            ResolutionStrategy::PathLookup
        );
        assert_eq!(ResolutionStrategy::CommandV, ResolutionStrategy::CommandV);
    }

    #[test]
    fn resolution_strategy_distinct_variants_not_equal() {
        assert_ne!(
            ResolutionStrategy::ExplicitPath,
            ResolutionStrategy::PathLookup
        );
        assert_ne!(
            ResolutionStrategy::ExplicitPath,
            ResolutionStrategy::CommandV
        );
        assert_ne!(ResolutionStrategy::PathLookup, ResolutionStrategy::CommandV);
    }

    #[test]
    fn resolved_program_struct_construction() {
        let prog = ResolvedProgram {
            path: PathBuf::from("/usr/bin/npm"),
            fixed_args: vec!["--version".into()],
            strategy: ResolutionStrategy::ExplicitPath,
            shell_hint: Some("bash".into()),
        };
        assert_eq!(prog.path, PathBuf::from("/usr/bin/npm"));
        assert_eq!(prog.fixed_args.len(), 1);
        assert_eq!(prog.strategy, ResolutionStrategy::ExplicitPath);
        assert_eq!(prog.shell_hint.as_deref(), Some("bash"));
    }

    #[test]
    fn resolved_program_clone_is_equal() {
        let prog = ResolvedProgram {
            path: PathBuf::from("/bin/sh"),
            fixed_args: vec![],
            strategy: ResolutionStrategy::PathLookup,
            shell_hint: None,
        };
        let cloned = prog.clone();
        assert_eq!(prog.path, cloned.path);
        assert_eq!(prog.strategy, cloned.strategy);
        assert_eq!(prog.shell_hint, cloned.shell_hint);
    }

    #[test]
    fn binding_record_empty_metadata_roundtrips() {
        let record = BindingRecord {
            id: BindingId::new("x"),
            label: "l".into(),
            target: "t".into(),
            secret_env_var: "S".into(),
            metadata: Default::default(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: BindingRecord = serde_json::from_str(&json).unwrap();
        assert!(parsed.metadata.is_empty());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingRecord {
    pub id: BindingId,
    pub label: String,
    pub target: String,
    pub secret_env_var: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStrategy {
    ExplicitPath,
    PathLookup,
    CommandV,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProgram {
    pub path: PathBuf,
    pub fixed_args: Vec<String>,
    pub strategy: ResolutionStrategy,
    pub shell_hint: Option<String>,
}
