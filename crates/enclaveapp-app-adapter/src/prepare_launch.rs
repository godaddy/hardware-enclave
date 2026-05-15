#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used))]

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::app_spec::{AppSpec, ConfigOverride};
use crate::error::{AdapterError, Result};
use crate::launcher::LaunchRequest;
use crate::temp_config::TempConfig;
use crate::types::{IntegrationType, ResolvedProgram};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrationPayload {
    HelperTool {
        env_overrides: BTreeMap<String, String>,
        extra_args: Vec<String>,
    },
    EnvInterpolation {
        config_bytes: Option<Vec<u8>>,
        env_overrides: BTreeMap<String, String>,
    },
    TempMaterializedConfig {
        config_bytes: Vec<u8>,
        env_overrides: BTreeMap<String, String>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntegrationCandidates {
    pub helper_tool: Option<IntegrationPayload>,
    pub env_interpolation: Option<IntegrationPayload>,
    pub temp_materialized_config: Option<IntegrationPayload>,
}

#[derive(Debug)]
pub struct PreparedAppLaunch {
    pub launch: LaunchRequest,
    pub temp_config_path: Option<std::path::PathBuf>,
    temp_config: Option<Arc<TempConfig>>,
}

pub fn prepare_best_app_launch(
    app_spec: &AppSpec,
    program: ResolvedProgram,
    args: Vec<String>,
    candidates: IntegrationCandidates,
) -> Result<PreparedAppLaunch> {
    for integration in [
        IntegrationType::HelperTool,
        IntegrationType::EnvInterpolation,
        IntegrationType::TempMaterializedConfig,
    ] {
        if !app_spec.supports(integration) {
            continue;
        }
        if let Some(payload) = candidates.payload_for(integration) {
            return prepare_app_launch(app_spec, program, args, payload);
        }
    }

    Err(AdapterError::NoAvailableIntegrationCandidate)
}

pub fn prepare_app_launch(
    app_spec: &AppSpec,
    program: ResolvedProgram,
    args: Vec<String>,
    payload: IntegrationPayload,
) -> Result<PreparedAppLaunch> {
    let integration = payload.integration_type();
    if !app_spec.supports(integration) {
        return Err(AdapterError::UnsupportedIntegration {
            app: app_spec.display_name.clone(),
            integration: format!("{integration:?}"),
        });
    }

    match payload {
        IntegrationPayload::HelperTool {
            env_overrides,
            extra_args,
        } => prepare_without_temp(app_spec, program, args, env_overrides, extra_args),
        IntegrationPayload::EnvInterpolation {
            config_bytes,
            env_overrides,
        } => {
            if let Some(config_bytes) = config_bytes {
                prepare_with_temp(
                    app_spec,
                    program,
                    args,
                    env_overrides,
                    config_bytes,
                    IntegrationType::EnvInterpolation,
                )
            } else {
                prepare_without_temp(app_spec, program, args, env_overrides, Vec::new())
            }
        }
        IntegrationPayload::TempMaterializedConfig {
            config_bytes,
            env_overrides,
        } => prepare_with_temp(
            app_spec,
            program,
            args,
            env_overrides,
            config_bytes,
            IntegrationType::TempMaterializedConfig,
        ),
    }
}

impl IntegrationPayload {
    fn integration_type(&self) -> IntegrationType {
        match self {
            Self::HelperTool { .. } => IntegrationType::HelperTool,
            Self::EnvInterpolation { .. } => IntegrationType::EnvInterpolation,
            Self::TempMaterializedConfig { .. } => IntegrationType::TempMaterializedConfig,
        }
    }
}

impl IntegrationCandidates {
    fn payload_for(&self, integration: IntegrationType) -> Option<IntegrationPayload> {
        match integration {
            IntegrationType::HelperTool => self.helper_tool.clone(),
            IntegrationType::EnvInterpolation => self.env_interpolation.clone(),
            IntegrationType::TempMaterializedConfig => self.temp_materialized_config.clone(),
        }
    }
}

fn prepare_without_temp(
    _app_spec: &AppSpec,
    program: ResolvedProgram,
    mut args: Vec<String>,
    env_overrides: BTreeMap<String, String>,
    mut extra_args: Vec<String>,
) -> Result<PreparedAppLaunch> {
    let mut launch_args = Vec::new();
    launch_args.append(&mut extra_args);
    launch_args.append(&mut args);

    Ok(PreparedAppLaunch {
        launch: LaunchRequest {
            program,
            args: launch_args,
            env_overrides,
            env_removals: Vec::new(),
            env_scrub_patterns: Vec::new(),
        },
        temp_config_path: None,
        temp_config: None,
    })
}

fn prepare_with_temp(
    app_spec: &AppSpec,
    program: ResolvedProgram,
    mut args: Vec<String>,
    mut env_overrides: BTreeMap<String, String>,
    config_bytes: Vec<u8>,
    _integration: IntegrationType,
) -> Result<PreparedAppLaunch> {
    let temp_config = Arc::new(TempConfig::write(
        &format!("{}-", app_spec.executable_name),
        "config",
        &config_bytes,
    )?);
    let temp_path = temp_config.path().to_path_buf();

    match &app_spec.config_override {
        ConfigOverride::EnvironmentVariable { name } => {
            env_overrides.insert(name.clone(), temp_path.to_string_lossy().into_owned());
        }
        ConfigOverride::CommandLineFlag { flag } => {
            args.insert(0, temp_path.to_string_lossy().into_owned());
            args.insert(0, flag.clone());
        }
        ConfigOverride::None => {
            return Err(AdapterError::MissingConfigOverride);
        }
    }

    Ok(PreparedAppLaunch {
        launch: LaunchRequest {
            program,
            args,
            env_overrides,
            env_removals: Vec::new(),
            env_scrub_patterns: Vec::new(),
        },
        temp_config_path: Some(temp_path),
        temp_config: Some(temp_config),
    })
}

impl PreparedAppLaunch {
    pub fn into_parts(
        self,
    ) -> (
        LaunchRequest,
        Option<std::path::PathBuf>,
        Option<Arc<TempConfig>>,
    ) {
        (self.launch, self.temp_config_path, self.temp_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ResolutionStrategy;

    fn resolved_program() -> ResolvedProgram {
        ResolvedProgram {
            path: "/bin/echo".into(),
            fixed_args: Vec::new(),
            strategy: ResolutionStrategy::ExplicitPath,
            shell_hint: None,
        }
    }

    #[test]
    fn prepares_env_interpolation_launch_with_temp_file() {
        let spec = AppSpec {
            display_name: "npm".into(),
            executable_name: "npm".into(),
            supported_integrations: vec![IntegrationType::EnvInterpolation],
            config_override: ConfigOverride::EnvironmentVariable {
                name: "NPM_CONFIG_USERCONFIG".into(),
            },
        };

        let prepared = prepare_app_launch(
            &spec,
            resolved_program(),
            vec!["install".into()],
            IntegrationPayload::EnvInterpolation {
                config_bytes: Some(b"//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n".to_vec()),
                env_overrides: BTreeMap::from([("NPM_TOKEN".into(), "secret".into())]),
            },
        )
        .expect("prepared");

        assert!(prepared.temp_config_path.is_some());
        assert!(prepared
            .launch
            .env_overrides
            .contains_key("NPM_CONFIG_USERCONFIG"));
    }

    #[test]
    fn prepares_temp_materialized_launch_with_flag_override() {
        let spec = AppSpec {
            display_name: "hopeless".into(),
            executable_name: "hopeless".into(),
            supported_integrations: vec![IntegrationType::TempMaterializedConfig],
            config_override: ConfigOverride::CommandLineFlag {
                flag: "--config".into(),
            },
        };

        let prepared = prepare_app_launch(
            &spec,
            resolved_program(),
            vec!["run".into()],
            IntegrationPayload::TempMaterializedConfig {
                config_bytes: b"token=abc\n".to_vec(),
                env_overrides: BTreeMap::new(),
            },
        )
        .expect("prepared");

        assert_eq!(prepared.launch.args[0], "--config");
        assert_eq!(prepared.launch.args[2], "run");
        assert!(prepared.temp_config_path.is_some());
    }

    #[test]
    fn prepares_helper_tool_launch_without_temp_config() {
        let spec = AppSpec {
            display_name: "helper-app".into(),
            executable_name: "helper-app".into(),
            supported_integrations: vec![IntegrationType::HelperTool],
            config_override: ConfigOverride::None,
        };

        let prepared = prepare_app_launch(
            &spec,
            resolved_program(),
            vec!["publish".into()],
            IntegrationPayload::HelperTool {
                env_overrides: BTreeMap::from([(
                    "HELPER_SOCKET".into(),
                    "/tmp/helper.sock".into(),
                )]),
                extra_args: vec!["--auth-helper".into(), "helper-bin".into()],
            },
        )
        .expect("prepared");

        assert!(prepared.temp_config_path.is_none());
        assert_eq!(
            prepared.launch.args,
            vec!["--auth-helper", "helper-bin", "publish"]
        );
        assert_eq!(
            prepared.launch.env_overrides.get("HELPER_SOCKET"),
            Some(&"/tmp/helper.sock".to_string())
        );
    }

    #[test]
    fn rejects_unsupported_integration_payload() {
        let spec = AppSpec {
            display_name: "env-only".into(),
            executable_name: "env-only".into(),
            supported_integrations: vec![IntegrationType::EnvInterpolation],
            config_override: ConfigOverride::EnvironmentVariable {
                name: "APP_CONFIG".into(),
            },
        };

        let error = prepare_app_launch(
            &spec,
            resolved_program(),
            vec!["run".into()],
            IntegrationPayload::TempMaterializedConfig {
                config_bytes: b"token=abc\n".to_vec(),
                env_overrides: BTreeMap::new(),
            },
        )
        .expect_err("unsupported integration should fail");

        assert!(matches!(error, AdapterError::UnsupportedIntegration { .. }));
    }

    #[test]
    fn prepares_best_launch_using_least_secret_exposing_available_candidate() {
        let spec = AppSpec {
            display_name: "generic-app".into(),
            executable_name: "generic-app".into(),
            supported_integrations: vec![
                IntegrationType::TempMaterializedConfig,
                IntegrationType::EnvInterpolation,
            ],
            config_override: ConfigOverride::EnvironmentVariable {
                name: "APP_CONFIG".into(),
            },
        };

        let prepared = prepare_best_app_launch(
            &spec,
            resolved_program(),
            vec!["run".into()],
            IntegrationCandidates {
                env_interpolation: Some(IntegrationPayload::EnvInterpolation {
                    config_bytes: Some(b"token=${APP_TOKEN}\n".to_vec()),
                    env_overrides: BTreeMap::from([("APP_TOKEN".into(), "secret".into())]),
                }),
                temp_materialized_config: Some(IntegrationPayload::TempMaterializedConfig {
                    config_bytes: b"token=materialized\n".to_vec(),
                    env_overrides: BTreeMap::new(),
                }),
                helper_tool: None,
            },
        )
        .expect("prepared");

        assert!(prepared.temp_config_path.is_some());
        assert_eq!(
            prepared.launch.env_overrides.get("APP_TOKEN"),
            Some(&"secret".to_string())
        );
    }

    #[test]
    fn missing_config_override_when_none_used_with_temp_materialized_config() {
        // ConfigOverride::None is not valid for TempMaterializedConfig —
        // the launcher would have nowhere to write the path.
        let spec = AppSpec {
            display_name: "no-override".into(),
            executable_name: "no-override".into(),
            supported_integrations: vec![IntegrationType::TempMaterializedConfig],
            config_override: ConfigOverride::None,
        };

        let error = prepare_app_launch(
            &spec,
            resolved_program(),
            Vec::new(),
            IntegrationPayload::TempMaterializedConfig {
                config_bytes: b"token=abc\n".to_vec(),
                env_overrides: BTreeMap::new(),
            },
        )
        .expect_err("ConfigOverride::None with TempMaterializedConfig must fail");

        assert!(
            matches!(error, AdapterError::MissingConfigOverride),
            "expected MissingConfigOverride, got: {error:?}"
        );
    }

    #[test]
    fn helper_tool_selected_first_when_all_three_integrations_supported() {
        // The priority order is HelperTool > EnvInterpolation > TempMaterializedConfig.
        // When all three are both supported and available, HelperTool must win.
        let spec = AppSpec {
            display_name: "all-three".into(),
            executable_name: "all-three".into(),
            supported_integrations: vec![
                IntegrationType::HelperTool,
                IntegrationType::EnvInterpolation,
                IntegrationType::TempMaterializedConfig,
            ],
            config_override: ConfigOverride::EnvironmentVariable {
                name: "CONFIG".into(),
            },
        };

        let prepared = prepare_best_app_launch(
            &spec,
            resolved_program(),
            Vec::new(),
            IntegrationCandidates {
                helper_tool: Some(IntegrationPayload::HelperTool {
                    env_overrides: BTreeMap::from([("HELPER_SOCKET".into(), "/sock".into())]),
                    extra_args: Vec::new(),
                }),
                env_interpolation: Some(IntegrationPayload::EnvInterpolation {
                    config_bytes: None,
                    env_overrides: BTreeMap::new(),
                }),
                temp_materialized_config: Some(IntegrationPayload::TempMaterializedConfig {
                    config_bytes: b"token=mat\n".to_vec(),
                    env_overrides: BTreeMap::new(),
                }),
            },
        )
        .expect("should succeed");

        // HelperTool path: no temp file, has HELPER_SOCKET override.
        assert!(
            prepared.temp_config_path.is_none(),
            "HelperTool should not produce a temp config"
        );
        assert!(
            prepared.launch.env_overrides.contains_key("HELPER_SOCKET"),
            "HelperTool override must be present"
        );
    }

    #[test]
    fn best_launch_errors_when_no_candidate_matches() {
        let spec = AppSpec {
            display_name: "helper-only".into(),
            executable_name: "helper-only".into(),
            supported_integrations: vec![IntegrationType::HelperTool],
            config_override: ConfigOverride::None,
        };

        let error = prepare_best_app_launch(
            &spec,
            resolved_program(),
            vec!["run".into()],
            IntegrationCandidates {
                env_interpolation: Some(IntegrationPayload::EnvInterpolation {
                    config_bytes: None,
                    env_overrides: BTreeMap::new(),
                }),
                ..IntegrationCandidates::default()
            },
        )
        .expect_err("no matching candidate");

        assert!(matches!(
            error,
            AdapterError::NoAvailableIntegrationCandidate
        ));
    }

    #[test]
    fn prepared_launch_without_temp_config_has_no_temp_config_path() {
        let spec = AppSpec {
            display_name: "tool".into(),
            executable_name: "tool".into(),
            supported_integrations: vec![IntegrationType::HelperTool],
            config_override: ConfigOverride::None,
        };
        let prepared = prepare_app_launch(
            &spec,
            resolved_program(),
            Vec::new(),
            IntegrationPayload::HelperTool {
                env_overrides: BTreeMap::new(),
                extra_args: Vec::new(),
            },
        )
        .unwrap();
        let (launch, temp_path, temp_config) = prepared.into_parts();
        assert!(temp_path.is_none());
        assert!(temp_config.is_none());
        assert!(launch.env_removals.is_empty());
        assert!(launch.env_scrub_patterns.is_empty());
    }

    #[test]
    fn env_interpolation_without_config_bytes_produces_no_temp_file() {
        let spec = AppSpec {
            display_name: "npm".into(),
            executable_name: "npm".into(),
            supported_integrations: vec![IntegrationType::EnvInterpolation],
            config_override: ConfigOverride::EnvironmentVariable {
                name: "NPM_CONFIG_USERCONFIG".into(),
            },
        };
        let prepared = prepare_app_launch(
            &spec,
            resolved_program(),
            vec!["install".into()],
            IntegrationPayload::EnvInterpolation {
                config_bytes: None,
                env_overrides: BTreeMap::from([("NPM_TOKEN".into(), "tok".into())]),
            },
        )
        .unwrap();
        assert!(prepared.temp_config_path.is_none());
        assert!(prepared.launch.env_overrides.contains_key("NPM_TOKEN"));
    }
}
