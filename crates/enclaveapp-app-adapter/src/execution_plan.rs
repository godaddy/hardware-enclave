#![cfg_attr(test, allow(clippy::unwrap_used))]

use crate::error::{AdapterError, Result};
use crate::types::IntegrationType;

/// Select the least-secret-exposing integration type from the app's supported list.
///
/// Priority order (most secure first):
/// 1. `HelperTool` — secrets never leave process
/// 2. `EnvInterpolation` — secrets in env vars only
/// 3. `TempMaterializedConfig` — secrets briefly on disk
pub fn choose_integration(supported: &[IntegrationType]) -> Result<IntegrationType> {
    if supported.contains(&IntegrationType::HelperTool) {
        return Ok(IntegrationType::HelperTool);
    }

    if supported.contains(&IntegrationType::EnvInterpolation) {
        return Ok(IntegrationType::EnvInterpolation);
    }

    if supported.contains(&IntegrationType::TempMaterializedConfig) {
        return Ok(IntegrationType::TempMaterializedConfig);
    }

    Err(AdapterError::NoSupportedIntegration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_least_secret_exposing_mode() {
        let supported = [
            IntegrationType::TempMaterializedConfig,
            IntegrationType::EnvInterpolation,
        ];

        assert_eq!(
            choose_integration(&supported).expect("integration"),
            IntegrationType::EnvInterpolation
        );
    }

    #[test]
    fn empty_supported_list_returns_error() {
        let result = choose_integration(&[]);
        assert!(
            matches!(result, Err(AdapterError::NoSupportedIntegration)),
            "empty list must produce NoSupportedIntegration"
        );
    }

    #[test]
    fn only_temp_materialized_config_is_selected() {
        let result = choose_integration(&[IntegrationType::TempMaterializedConfig]);
        assert_eq!(result.unwrap(), IntegrationType::TempMaterializedConfig);
    }

    #[test]
    fn helper_tool_wins_over_env_interpolation() {
        let supported = [
            IntegrationType::EnvInterpolation,
            IntegrationType::HelperTool,
        ];
        assert_eq!(
            choose_integration(&supported).unwrap(),
            IntegrationType::HelperTool,
            "HelperTool must beat EnvInterpolation"
        );
    }

    #[test]
    fn helper_tool_wins_over_temp_materialized_config() {
        let supported = [
            IntegrationType::TempMaterializedConfig,
            IntegrationType::HelperTool,
        ];
        assert_eq!(
            choose_integration(&supported).unwrap(),
            IntegrationType::HelperTool
        );
    }

    #[test]
    fn env_interpolation_wins_over_temp_materialized_config() {
        let supported = [
            IntegrationType::TempMaterializedConfig,
            IntegrationType::EnvInterpolation,
        ];
        assert_eq!(
            choose_integration(&supported).unwrap(),
            IntegrationType::EnvInterpolation
        );
    }

    #[test]
    fn only_env_interpolation_is_selected() {
        let result = choose_integration(&[IntegrationType::EnvInterpolation]);
        assert_eq!(result.unwrap(), IntegrationType::EnvInterpolation);
    }

    #[test]
    fn only_helper_tool_is_selected() {
        let result = choose_integration(&[IntegrationType::HelperTool]);
        assert_eq!(result.unwrap(), IntegrationType::HelperTool);
    }

    #[test]
    fn all_three_prefers_helper_tool() {
        let supported = [
            IntegrationType::TempMaterializedConfig,
            IntegrationType::EnvInterpolation,
            IntegrationType::HelperTool,
        ];
        assert_eq!(
            choose_integration(&supported).unwrap(),
            IntegrationType::HelperTool
        );
    }

    #[test]
    fn duplicate_entries_still_selects_correct_priority() {
        let supported = [
            IntegrationType::EnvInterpolation,
            IntegrationType::EnvInterpolation,
        ];
        assert_eq!(
            choose_integration(&supported).unwrap(),
            IntegrationType::EnvInterpolation
        );
    }
}
