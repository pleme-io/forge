# Flake input management library
{ lib }:
let
  self = {
  # Input categories for organization
  categories = {
    core = [
      "nixpkgs"
      "flake-parts"
      "flake-utils"
    ];
    
    userEnvironment = [
      "home-manager"
      "nix-darwin"
      "stylix"
    ];
    
    desktop = [
      "hyprland"
      "hyprland-plugins"
    ];

    security = [
      "sops-nix"
    ];
  };
  
  # Get all inputs from categories
  getAllInputs = categories:
    lib.flatten (lib.attrValues categories);
  
  # Input metadata and constraints
  inputMetadata = {
    nixpkgs = {
      description = "Nix packages collection";
      updateFrequency = "weekly";
      branch = "nixos-unstable";
      critical = true;
    };
    
    home-manager = {
      description = "User environment management";
      updateFrequency = "weekly";
      followsNixpkgs = true;
      critical = true;
    };
    
    flake-parts = {
      description = "Flake composition framework";
      updateFrequency = "monthly";
      critical = true;
    };
    
    sops-nix = {
      description = "Secrets management";
      updateFrequency = "monthly";
      critical = true;
    };
    
    hyprland = {
      description = "Wayland compositor";
      updateFrequency = "weekly";
      followsNixpkgs = true;
      critical = false;
    };
    
    stylix = {
      description = "System theming";
      updateFrequency = "monthly";
      critical = false;
    };
    
    nix-darwin = {
      description = "macOS configuration";
      updateFrequency = "monthly";
      followsNixpkgs = true;
      critical = false;
    };
  };
  
  # Check if input should be updated
  shouldUpdate = inputName: lastUpdateTime: currentTime:
    let
      metadata = self.inputMetadata.${inputName} or {};
      frequency = metadata.updateFrequency or "monthly";
      daysSinceUpdate = (currentTime - lastUpdateTime) / 86400;
      
      thresholds = {
        daily = 1;
        weekly = 7;
        biweekly = 14;
        monthly = 30;
        quarterly = 90;
      };
      
      threshold = thresholds.${frequency} or 30;
    in
      daysSinceUpdate >= threshold;
  
  # Generate input specification
  mkInputSpec = { url, follows ? null, flake ? true }:
    { inherit url flake; } // 
    (if follows != null then { inputs.nixpkgs.follows = follows; } else {});
  
  # Standard input patterns
  patterns = {
    github = owner: repo: branch:
      "github:${owner}/${repo}/${branch}";
    
    githubDefault = owner: repo:
      "github:${owner}/${repo}";
    
    git = url: branch:
      "git+${url}?ref=${branch}";
    
    flakeRegistry = name:
      "flake:${name}";
  };
  
  # Input health checks
  checks = {
    # Check if input exists in lock
    exists = lock: inputName:
      lock.nodes ? ${inputName};
    
    # Check if input is stale
    isStale = lock: inputName: currentTime:
      let
        node = lock.nodes.${inputName} or null;
        lastModified = node.locked.lastModified or 0;
      in
        if node != null then
          self.shouldUpdate inputName lastModified currentTime
        else
          false;
    
    # Check for security updates
    hasSecurityUpdate = lock: inputName:
      # This would check CVE databases in a real implementation
      false;
    
    # Check input consistency
    isConsistent = lock: inputName:
      let
        node = lock.nodes.${inputName} or null;
        original = node.original or {};
        locked = node.locked or {};
      in
        if node != null then
          original.type == locked.type
        else
          false;
  };
  
  # Input update strategies
  updateStrategies = {
    # Conservative: Only security updates
    conservative = inputs: lock: currentTime:
      lib.filterAttrs (name: _:
        self.checks.hasSecurityUpdate lock name
      ) inputs;
    
    # Regular: Follow update frequency
    regular = inputs: lock: currentTime:
      lib.filterAttrs (name: _:
        self.checks.isStale lock name currentTime ||
        self.checks.hasSecurityUpdate lock name
      ) inputs;
    
    # Aggressive: Update all
    aggressive = inputs: lock: currentTime:
      inputs;
    
    # Staged: Update by category
    staged = category: inputs: lock: currentTime:
      lib.filterAttrs (name: _:
        lib.elem name (self.categories.${category} or [])
      ) inputs;
  };
  
  # Pin management
  pins = {
    # Create pin entry
    mkPin = rev: narHash: {
      type = "pin";
      inherit rev narHash;
    };
    
    # Pin current state
    pinCurrent = lock: inputName:
      let
        node = lock.nodes.${inputName} or null;
      in
        if node != null then
          self.pins.mkPin node.locked.rev node.locked.narHash
        else
          null;
    
    # Check if pinned
    isPinned = lock: inputName:
      let
        node = lock.nodes.${inputName} or null;
      in
        node != null && node.original.type or "" == "pin";
  };
  
  # Dependency management
  dependencies = {
    # Get inputs that follow this one
    getFollowers = lock: inputName:
      lib.filterAttrs (name: node:
        node.inputs.nixpkgs.follows or "" == inputName
      ) lock.nodes;
    
    # Get transitive dependencies
    getTransitive = lock: inputName:
      let
        direct = lock.nodes.${inputName}.inputs or {};
        indirect = lib.mapAttrs (name: _:
          self.dependencies.getTransitive lock name
        ) direct;
      in
        direct // lib.foldl' (a: b: a // b) {} (lib.attrValues indirect);
  };
  
  # Update scripts
  scripts = {
    # Update single input
    updateInput = inputName:
      ''nix flake lock --update-input ${inputName}'';
    
    # Update category
    updateCategory = category:
      let
        inputs = self.categories.${category} or [];
        updates = map (i: "--update-input ${i}") inputs;
      in
        ''nix flake lock ${lib.concatStringsSep " " updates}'';
    
    # Update with strategy
    updateWithStrategy = strategy:
      ''
        # This would be implemented as a full script
        echo "Updating with ${strategy} strategy"
      '';
  };
  
  # Reporting functions
  reports = {
    # Generate update report
    updateReport = lock: currentTime:
      let
        staleInputs = lib.filterAttrs (name: _:
          self.checks.isStale lock name currentTime
        ) lock.nodes;
      in
        lib.mapAttrs (name: node: {
          lastModified = node.locked.lastModified or 0;
          daysSinceUpdate = (currentTime - (node.locked.lastModified or 0)) / 86400;
          updateFrequency = (self.inputMetadata.${name} or {}).updateFrequency or "unknown";
        }) staleInputs;
    
    # Generate health report
    healthReport = lock:
      lib.mapAttrs (name: node: {
        exists = self.checks.exists lock name;
        consistent = self.checks.isConsistent lock name;
        pinned = self.pins.isPinned lock name;
        followers = lib.attrNames (self.dependencies.getFollowers lock name);
      }) lock.nodes;
  };
  };
in self