//! Release service - orchestrates the release workflow
//!
//! This service coordinates all steps of a release:
//! push, deploy, migrate, schema extraction, federation update.

use anyhow::{Context, Result};
use colored::Colorize;
use std::time::Instant;
use tracing::info;

use crate::domain::release::{ReleaseConfig, ReleasePhase, ReleaseStep, StepResult};
use crate::infrastructure::git::GitClient;
use crate::infrastructure::registry::RegistryClient;

/// Service for orchestrating releases
pub struct ReleaseService {
    git: GitClient,
}

impl ReleaseService {
    /// Create a new release service
    pub fn new() -> Self {
        Self {
            git: GitClient::new(),
        }
    }

    /// Execute a full release workflow
    pub async fn execute(&self, config: ReleaseConfig) -> Result<Vec<StepResult>> {
        // Validate configuration
        config.validate().map_err(|errors| {
            anyhow::anyhow!("Invalid release configuration:\n  {}", errors.join("\n  "))
        })?;

        self.print_header(&config);

        let mut results = Vec::new();
        let mut current_phase = ReleasePhase::Pending;

        for step in &config.steps {
            current_phase = ReleasePhase::InProgress(*step);
            info!("{} Starting: {}", step.emoji(), step.name());

            let start = Instant::now();
            let result = self.execute_step(&config, *step).await;
            let duration = start.elapsed();

            match result {
                Ok(()) => {
                    info!(
                        "{} {} completed in {:.1}s",
                        "✅".green(),
                        step.name(),
                        duration.as_secs_f64()
                    );
                    results.push(StepResult::success(*step, duration));
                }
                Err(e) => {
                    let msg = format!("{:#}", e);
                    info!("{} {} failed: {}", "❌".red(), step.name(), msg);
                    results.push(StepResult::failure(*step, duration, &msg));
                    current_phase = ReleasePhase::Failed(*step);

                    // Stop on first failure
                    self.print_summary(&config, &results, current_phase);
                    return Err(e);
                }
            }
        }

        current_phase = ReleasePhase::Completed;
        self.print_summary(&config, &results, current_phase);

        Ok(results)
    }

    /// Execute a single release step
    async fn execute_step(&self, config: &ReleaseConfig, step: ReleaseStep) -> Result<()> {
        match step {
            ReleaseStep::Build => self.step_build(config).await,
            ReleaseStep::Push => self.step_push(config).await,
            ReleaseStep::Deploy => self.step_deploy(config).await,
            ReleaseStep::FluxReconcile => self.step_flux_reconcile(config).await,
            ReleaseStep::Migrate => self.step_migrate(config).await,
            ReleaseStep::ExtractSchema => self.step_extract_schema(config).await,
            ReleaseStep::UpdateFederation => self.step_update_federation(config).await,
            ReleaseStep::IntegrationTests => self.step_integration_tests(config).await,
            ReleaseStep::Rollout => self.step_rollout(config).await,
        }
    }

    // Step implementations - these will delegate to infrastructure

    async fn step_build(&self, config: &ReleaseConfig) -> Result<()> {
        info!("Building image for {}", config.service);
        // TODO: Delegate to NixBuilder
        Ok(())
    }

    async fn step_push(&self, config: &ReleaseConfig) -> Result<()> {
        info!("Pushing {} to {}", config.image_path, config.registry);
        // TODO: Delegate to RegistryClient
        Ok(())
    }

    async fn step_deploy(&self, config: &ReleaseConfig) -> Result<()> {
        info!("Updating manifest at {}", config.manifest_path);
        // TODO: Update kustomization.yaml and commit
        Ok(())
    }

    async fn step_flux_reconcile(&self, config: &ReleaseConfig) -> Result<()> {
        info!("Waiting for Flux reconciliation in {}", config.namespace);
        // TODO: Delegate to FluxClient
        Ok(())
    }

    async fn step_migrate(&self, config: &ReleaseConfig) -> Result<()> {
        info!("Running migrations for {}", config.service);
        // TODO: Delegate to MigrationService
        Ok(())
    }

    async fn step_extract_schema(&self, config: &ReleaseConfig) -> Result<()> {
        info!("Extracting GraphQL schema for {}", config.service);
        // TODO: Delegate to SchemaService
        Ok(())
    }

    async fn step_update_federation(&self, config: &ReleaseConfig) -> Result<()> {
        info!("Updating Apollo Federation supergraph");
        // TODO: Delegate to FederationService
        Ok(())
    }

    async fn step_integration_tests(&self, config: &ReleaseConfig) -> Result<()> {
        info!("Running integration tests for {}", config.service);
        // TODO: Delegate to TestService
        Ok(())
    }

    async fn step_rollout(&self, config: &ReleaseConfig) -> Result<()> {
        if !config.watch_rollout {
            info!("Skipping rollout monitoring (--no-watch)");
            return Ok(());
        }
        info!("Monitoring rollout for {}", config.service);
        // TODO: Delegate to RolloutMonitor
        Ok(())
    }

    fn print_header(&self, config: &ReleaseConfig) {
        println!();
        println!(
            "{}",
            "╔════════════════════════════════════════════════════════════╗".bright_blue()
        );
        println!(
            "{}",
            format!(
                "║  Release: {:<49} ║",
                format!("{}/{}", config.product, config.service)
            )
            .bright_blue()
        );
        println!(
            "{}",
            "╚════════════════════════════════════════════════════════════╝".bright_blue()
        );
        println!();
        info!("Namespace: {}", config.namespace);
        info!("Registry: {}", config.registry);
        info!("Steps: {}", config.steps.len());
        println!();
    }

    fn print_summary(&self, config: &ReleaseConfig, results: &[StepResult], phase: ReleasePhase) {
        println!();
        println!(
            "{}",
            "════════════════════════════════════════════════════════════".bright_blue()
        );

        match phase {
            ReleasePhase::Completed => {
                println!(
                    "{}",
                    format!(
                        "✅ Release completed: {}/{}",
                        config.product, config.service
                    )
                    .bright_green()
                    .bold()
                );
            }
            ReleasePhase::Failed(step) => {
                println!(
                    "{}",
                    format!(
                        "❌ Release failed at {}: {}/{}",
                        step.name(),
                        config.product,
                        config.service
                    )
                    .bright_red()
                    .bold()
                );
            }
            _ => {}
        }

        println!();
        for result in results {
            let status = if result.success { "✅" } else { "❌" };
            println!(
                "   {} {} ({:.1}s)",
                status,
                result.step.name(),
                result.duration.as_secs_f64()
            );
        }
        println!();
    }
}

impl Default for ReleaseService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_release_service_creation() {
        let service = ReleaseService::new();
        // Just verify it can be created
        assert!(true);
    }
}
