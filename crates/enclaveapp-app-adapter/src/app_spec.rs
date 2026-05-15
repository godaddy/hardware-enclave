#![cfg_attr(test, allow(clippy::panic))]

use crate::types::IntegrationType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigOverride {
    None,
    EnvironmentVariable { name: String },
    CommandLineFlag { flag: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSpec {
    pub display_name: String,
    pub executable_name: String,
    /// Which integration types this application supports, in order of preference.
    /// The adapter will select the first type that matches an available payload.
    pub supported_integrations: Vec<IntegrationType>,
    pub config_override: ConfigOverride,
}

impl AppSpec {
    pub fn supports(&self, integration: IntegrationType) -> bool {
        self.supported_integrations.contains(&integration)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn spec_with(types: Vec<IntegrationType>) -> AppSpec {
        AppSpec {
            display_name: "test-app".into(),
            executable_name: "test-app".into(),
            supported_integrations: types,
            config_override: ConfigOverride::None,
        }
    }

    #[test]
    fn supports_returns_true_when_integration_is_in_list() {
        let spec = spec_with(vec![
            IntegrationType::HelperTool,
            IntegrationType::EnvInterpolation,
        ]);
        assert!(spec.supports(IntegrationType::HelperTool));
        assert!(spec.supports(IntegrationType::EnvInterpolation));
    }

    #[test]
    fn supports_returns_false_when_integration_is_not_in_list() {
        let spec = spec_with(vec![IntegrationType::HelperTool]);
        assert!(!spec.supports(IntegrationType::EnvInterpolation));
        assert!(!spec.supports(IntegrationType::TempMaterializedConfig));
    }

    #[test]
    fn supports_returns_false_for_empty_supported_list() {
        let spec = spec_with(Vec::new());
        assert!(!spec.supports(IntegrationType::HelperTool));
        assert!(!spec.supports(IntegrationType::EnvInterpolation));
        assert!(!spec.supports(IntegrationType::TempMaterializedConfig));
    }

    #[test]
    fn config_override_none_variant_equality() {
        assert_eq!(ConfigOverride::None, ConfigOverride::None);
    }

    #[test]
    fn config_override_environment_variable_stores_name() {
        let co = ConfigOverride::EnvironmentVariable {
            name: "MY_TOKEN".into(),
        };
        if let ConfigOverride::EnvironmentVariable { name } = co {
            assert_eq!(name, "MY_TOKEN");
        } else {
            panic!("expected EnvironmentVariable variant");
        }
    }

    #[test]
    fn config_override_command_line_flag_stores_flag() {
        let co = ConfigOverride::CommandLineFlag {
            flag: "--config".into(),
        };
        if let ConfigOverride::CommandLineFlag { flag } = co {
            assert_eq!(flag, "--config");
        } else {
            panic!("expected CommandLineFlag variant");
        }
    }

    #[test]
    fn config_override_different_variants_are_not_equal() {
        let env_var = ConfigOverride::EnvironmentVariable { name: "X".into() };
        let cli_flag = ConfigOverride::CommandLineFlag { flag: "--x".into() };
        assert_ne!(env_var, ConfigOverride::None);
        assert_ne!(cli_flag, ConfigOverride::None);
        assert_ne!(env_var, cli_flag);
    }

    #[test]
    fn app_spec_clone_is_equal() {
        let spec = AppSpec {
            display_name: "My App".into(),
            executable_name: "myapp".into(),
            supported_integrations: vec![IntegrationType::EnvInterpolation],
            config_override: ConfigOverride::CommandLineFlag {
                flag: "--token".into(),
            },
        };
        let cloned = spec.clone();
        assert_eq!(spec.display_name, cloned.display_name);
        assert_eq!(spec.executable_name, cloned.executable_name);
        assert_eq!(spec.supported_integrations, cloned.supported_integrations);
        assert_eq!(spec.config_override, cloned.config_override);
    }

    #[test]
    fn supports_all_three_integration_types_when_all_listed() {
        let spec = spec_with(vec![
            IntegrationType::HelperTool,
            IntegrationType::EnvInterpolation,
            IntegrationType::TempMaterializedConfig,
        ]);
        assert!(spec.supports(IntegrationType::HelperTool));
        assert!(spec.supports(IntegrationType::EnvInterpolation));
        assert!(spec.supports(IntegrationType::TempMaterializedConfig));
    }

    #[test]
    fn supports_temp_materialized_config_only() {
        let spec = spec_with(vec![IntegrationType::TempMaterializedConfig]);
        assert!(spec.supports(IntegrationType::TempMaterializedConfig));
        assert!(!spec.supports(IntegrationType::HelperTool));
        assert!(!spec.supports(IntegrationType::EnvInterpolation));
    }
}
