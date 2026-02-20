//! Service domain types
//!
//! Defines service configuration and metadata.

use super::migration::DatabaseType;

/// Get the registry base URL from environment or use a placeholder
/// In production, this should be configured via deploy.yaml
fn get_registry_base() -> String {
    std::env::var("SERVICE_REGISTRY_BASE").unwrap_or_else(|_| "ghcr.io/org/project".to_string())
}

/// Types of services in the system
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    /// Rust microservice with GraphQL
    Rust,
    /// Web frontend (React/Next.js + Hanabi BFF)
    Web,
    /// WASM frontend (Yew + Hanabi)
    Wasm,
    /// Infrastructure tool (bootstrap, operators)
    Infrastructure,
    /// Platform service (Pangea components)
    Platform,
}

impl ServiceType {
    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rust" => Some(Self::Rust),
            "web" => Some(Self::Web),
            "wasm" => Some(Self::Wasm),
            "infrastructure" | "infra" => Some(Self::Infrastructure),
            "platform" => Some(Self::Platform),
            _ => None,
        }
    }

    /// Get default flake attribute for this service type
    pub fn default_flake_attr(&self) -> &'static str {
        match self {
            Self::Rust => "dockerImage-amd64",
            Self::Web => "dockerImage",
            Self::Wasm => "dockerImage",
            Self::Infrastructure => "dockerImage",
            Self::Platform => "dockerImage",
        }
    }
}

/// Service definition with all metadata
#[derive(Debug, Clone)]
pub struct ServiceDefinition {
    /// Service name (e.g., "cart", "auth")
    pub name: String,
    /// Product name (e.g., "myapp")
    pub product: String,
    /// Service type
    pub service_type: ServiceType,
    /// Database type for migrations
    pub database_type: DatabaseType,
    /// Whether GraphQL schema extraction is enabled
    pub graphql_enabled: bool,
    /// Whether Apollo Federation is enabled
    pub federation_enabled: bool,
    /// Path to service directory (relative to repo root)
    pub service_dir: String,
    /// Container registry URL
    pub registry: String,
}

impl ServiceDefinition {
    /// Create a new Rust service definition
    pub fn rust(name: impl Into<String>, product: impl Into<String>) -> Self {
        let name = name.into();
        let product = product.into();
        Self {
            service_dir: format!("pkgs/products/{}/services/rust/{}", product, name),
            registry: format!("{}/{}-{}", get_registry_base(), product, name),
            name,
            product,
            service_type: ServiceType::Rust,
            database_type: DatabaseType::Postgres,
            graphql_enabled: true,
            federation_enabled: true,
        }
    }

    /// Create a new Web service definition
    pub fn web(name: impl Into<String>, product: impl Into<String>) -> Self {
        let name = name.into();
        let product = product.into();
        Self {
            service_dir: format!("pkgs/products/{}/services/web/{}", product, name),
            registry: format!("{}/{}-{}", get_registry_base(), product, name),
            name,
            product,
            service_type: ServiceType::Web,
            database_type: DatabaseType::None,
            graphql_enabled: false,
            federation_enabled: false,
        }
    }

    /// Create a platform service definition
    pub fn platform(name: impl Into<String>, component: impl Into<String>) -> Self {
        let name = name.into();
        let component = component.into();
        Self {
            service_dir: format!("pkgs/products/{}/{}-{}", name, name, component),
            registry: format!("{}/{}-{}", get_registry_base(), name, component),
            name: name.clone(),
            product: name,
            service_type: ServiceType::Platform,
            database_type: DatabaseType::None,
            graphql_enabled: false,
            federation_enabled: false,
        }
    }

    /// Builder: set database type
    pub fn with_database(mut self, db_type: DatabaseType) -> Self {
        self.database_type = db_type;
        self
    }

    /// Builder: enable/disable GraphQL
    pub fn with_graphql(mut self, enabled: bool) -> Self {
        self.graphql_enabled = enabled;
        self
    }

    /// Builder: enable/disable federation
    pub fn with_federation(mut self, enabled: bool) -> Self {
        self.federation_enabled = enabled;
        self
    }

    /// Builder: set service directory
    pub fn with_service_dir(mut self, dir: impl Into<String>) -> Self {
        self.service_dir = dir.into();
        self
    }

    /// Builder: set registry
    pub fn with_registry(mut self, registry: impl Into<String>) -> Self {
        self.registry = registry.into();
        self
    }

    /// Get the Kubernetes namespace for this service
    pub fn namespace(&self, environment: &str) -> String {
        format!("{}-{}", self.product, environment)
    }

    /// Get the Kubernetes deployment name
    pub fn deployment_name(&self) -> String {
        format!("{}-deployment", self.name)
    }

    /// Get the manifest path for a given cluster and environment
    pub fn manifest_path(&self, cluster: &str, environment: &str) -> String {
        format!(
            "nix/k8s/clusters/{}/products/{}-{}/services/{}/kustomization.yaml",
            cluster, self.product, environment, self.name
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_service_definition() {
        let service = ServiceDefinition::rust("api", "myproduct");

        assert_eq!(service.name, "api");
        assert_eq!(service.product, "myproduct");
        assert_eq!(service.service_type, ServiceType::Rust);
        assert_eq!(service.database_type, DatabaseType::Postgres);
        assert!(service.graphql_enabled);
        assert!(service.federation_enabled);
        assert_eq!(service.namespace("staging"), "myproduct-staging");
    }

    #[test]
    fn test_web_service_definition() {
        let service = ServiceDefinition::web("web", "testapp");

        assert_eq!(service.service_type, ServiceType::Web);
        assert_eq!(service.database_type, DatabaseType::None);
        assert!(!service.graphql_enabled);
    }

    #[test]
    fn test_platform_service_definition() {
        let service = ServiceDefinition::platform("platform", "operator");

        assert_eq!(service.service_type, ServiceType::Platform);
        // Registry uses get_registry_base() which defaults to "ghcr.io/org/project"
        assert!(service.registry.ends_with("/platform-operator"));
    }
}
