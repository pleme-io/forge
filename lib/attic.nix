# Attic Binary Cache Configuration
# Single source of truth for Attic cache settings
#
# Override these values in your consumer flake or via environment variables.
# See: https://docs.attic.rs/
{
  # Attic cache JWT token — inject via environment variable, never hardcode
  token = builtins.getEnv "ATTIC_TOKEN";

  # Cache configuration
  cache = {
    # Full URL with cache name for Nix substituters
    # Example: "http://cache.example.com/my-cache"
    url = builtins.getEnv "ATTIC_CACHE_URL";

    # Attic server hostname
    # Example: "cache.example.com"
    hostname = builtins.getEnv "ATTIC_HOSTNAME";

    # The cache name within Attic
    # Example: "my-cache"
    cacheName = builtins.getEnv "ATTIC_CACHE_NAME";

    # Public keys for verifying cache signatures
    # Generate with: attic cache info <cache-name>
    publicKeys = [];

    # Primary public key (current)
    publicKey = "";
  };
}
