# Cross-platform abstraction library
{ lib, stdenv ? null, system ? null }:
let
  # Determine current system/platform
  currentSystem = if system != null then system 
                  else if stdenv != null then stdenv.hostPlatform.system 
                  else "unknown";
  currentStdenv = if stdenv != null then stdenv 
                  else { isDarwin = false; isLinux = false; };
  
  self = {
    # Platform detection
    platform = {
      isDarwin = currentStdenv.isDarwin or false || (lib.hasSuffix "darwin" currentSystem);
      isLinux = currentStdenv.isLinux or false || (lib.hasInfix "linux" currentSystem);
      isNixOS = currentStdenv.isLinux && (builtins.pathExists /etc/nixos);
      
      # Architecture detection
      isAarch64 = lib.hasPrefix "aarch64" currentSystem;
      isX86_64 = lib.hasPrefix "x86_64" currentSystem;
      isAarch32 = lib.hasPrefix "armv" currentSystem;
      isI686 = lib.hasPrefix "i686" currentSystem;
      
      # Combined platform checks
      isAarch64Darwin = self.platform.isDarwin && self.platform.isAarch64;
      isX86_64Darwin = self.platform.isDarwin && self.platform.isX86_64;
      isAarch64Linux = self.platform.isLinux && self.platform.isAarch64;
      isX86_64Linux = self.platform.isLinux && self.platform.isX86_64;
      
      # System string
      system = currentSystem;
    };
    
    # Platform-specific path utilities
    paths = {
      # Home directory
      home = 
        if self.platform.isDarwin then
          "/Users"
        else
          "/home";
      
      # Temporary directory
      tmp = 
        if self.platform.isDarwin then
          "/private/tmp"
        else
          "/tmp";
      
      # Application directories
      applications = 
        if self.platform.isDarwin then
          "/Applications"
        else
          null;
      
      # System configuration
      systemConfig = 
        if self.platform.isNixOS then
          "/etc/nixos"
        else if self.platform.isDarwin then
          "/etc/nix/darwin"
        else
          null;
      
      # Library paths
      libDir = 
        if self.platform.isDarwin then
          "lib"
        else
          "lib64";
    };
    
    # Platform-specific commands
    commands = {
      # Package manager
      packageManager = 
        if self.platform.isNixOS then
          "nix"
        else if self.platform.isDarwin then
          "brew"
        else
          "apt";
      
      # Service management
      serviceManager = 
        if self.platform.isLinux then
          "systemctl"
        else if self.platform.isDarwin then
          "launchctl"
        else
          null;
      
      # Open command
      open = 
        if self.platform.isDarwin then
          "open"
        else if self.platform.isLinux then
          "xdg-open"
        else
          null;
      
      # Clipboard
      clipboard = {
        copy = 
          if self.platform.isDarwin then
            "pbcopy"
          else if self.platform.isLinux then
            "xclip -selection clipboard"
          else
            null;
        
        paste = 
          if self.platform.isDarwin then
            "pbpaste"
          else if self.platform.isLinux then
            "xclip -selection clipboard -o"
          else
            null;
      };
    };
    
    # Platform-specific package names
    packages = {
      # Core utilities that differ
      coreutils = 
        if self.platform.isDarwin then
          "coreutils"  # GNU coreutils
        else
          "coreutils";  # Already GNU on Linux
      
      # Find utilities
      find = 
        if self.platform.isDarwin then
          "findutils"  # GNU find
        else
          "findutils";
      
      # Sed
      sed = 
        if self.platform.isDarwin then
          "gnused"  # GNU sed
        else
          "gnused";
      
      # Make
      make = 
        if self.platform.isDarwin then
          "gnumake"
        else
          "gnumake";
    };
    
    # Platform conditionals
    when = {
      # Run only on Darwin
      darwin = expr: 
        if self.platform.isDarwin then expr else null;
      
      # Run only on Linux
      linux = expr: 
        if self.platform.isLinux then expr else null;
      
      # Run only on NixOS
      nixos = expr: 
        if self.platform.isNixOS then expr else null;
      
      # Run only on specific architecture
      aarch64 = expr:
        if self.platform.isAarch64 then expr else null;
      
      x86_64 = expr:
        if self.platform.isX86_64 then expr else null;
    };
    
    # Platform-specific mkDerivation arguments
    mkDerivationArgs = {
      # Darwin-specific build inputs
      # Note: stdenv now provides SDK automatically, so typically no extra inputs needed
      darwinBuildInputs =
        if self.platform.isDarwin then
          []  # SDK provided by stdenv; add specific SDK version here if needed
        else
          [];
      
      # Linux-specific build inputs
      linuxBuildInputs = 
        if self.platform.isLinux then
          []  # Add common Linux deps here
        else
          [];
      
      # Combined platform build inputs
      platformBuildInputs = 
        self.mkDerivationArgs.darwinBuildInputs ++
        self.mkDerivationArgs.linuxBuildInputs;
    };
    
    # Service definitions
    services = {
      # Create systemd service (Linux)
      mkSystemdService = { name, description, exec, ... }@args:
        if self.platform.isLinux then {
          systemd.services.${name} = {
            inherit description;
            serviceConfig = {
              ExecStart = exec;
              Restart = "always";
            } // (args.serviceConfig or {});
          } // (removeAttrs args [ "name" "description" "exec" "serviceConfig" ]);
        } else {};
      
      # Create launchd service (Darwin)
      mkLaunchdService = { name, description, exec, ... }@args:
        if self.platform.isDarwin then {
          launchd.daemons.${name} = {
            serviceConfig = {
              ProgramArguments = lib.splitString " " exec;
              RunAtLoad = true;
              KeepAlive = true;
            } // (args.serviceConfig or {});
          } // (removeAttrs args [ "name" "description" "exec" "serviceConfig" ]);
        } else {};
      
      # Universal service creator
      mkService = args:
        (self.services.mkSystemdService args) //
        (self.services.mkLaunchdService args);
    };
    
    # Shell/environment differences
    shell = {
      # Shell initialization file
      initFile = 
        if self.platform.isDarwin then
          ".zshrc"  # macOS defaults to zsh
        else
          ".bashrc";  # Linux usually bash
      
      # Profile file
      profileFile = 
        if self.platform.isDarwin then
          ".zprofile"
        else
          ".profile";
      
      # Default shell
      defaultShell = 
        if self.platform.isDarwin then
          "/bin/zsh"
        else
          "/bin/bash";
    };
    
    # GUI/Desktop differences
    desktop = {
      # Whether GUI is typically available
      hasGui = 
        if self.platform.isDarwin then
          true  # macOS always has GUI
        else
          false;  # Assume headless Linux by default
      
      # Display server
      displayServer = 
        if self.platform.isDarwin then
          "quartz"
        else if self.platform.isLinux then
          "x11"  # or "wayland"
        else
          null;
    };
    
    # Compatibility helpers
    compat = {
      # Make command work on both platforms
      mkCompatibleCommand = { darwin, linux, default ? "" }:
        if self.platform.isDarwin then
          darwin
        else if self.platform.isLinux then
          linux
        else
          default;
      
      # Choose package based on platform
      choosePkg = { darwin, linux, default ? null }:
        if self.platform.isDarwin then
          darwin
        else if self.platform.isLinux then
          linux
        else
          default;
    };
  };
in self