# Error reporting system for collecting and displaying errors
{ lib, pkgs }:
let
  errors = import ./errors.nix { inherit lib; };
  
  self = {
    # Error collection system
    collector = {
      # Create a new error collector
      new = {
        errors = [];
        warnings = [];
        info = [];
        hasErrors = false;
        hasWarnings = false;
      };
      
      # Add an error to collector
      addError = collector: error:
        collector // {
          errors = collector.errors ++ [ error ];
          hasErrors = true;
        };
      
      # Add a warning to collector
      addWarning = collector: warning:
        collector // {
          warnings = collector.warnings ++ [ warning ];
          hasWarnings = true;
        };
      
      # Add info message to collector
      addInfo = collector: info:
        collector // {
          info = collector.info ++ [ info ];
        };
      
      # Merge multiple collectors
      merge = collectors:
        lib.foldl' (acc: col: {
          errors = acc.errors ++ col.errors;
          warnings = acc.warnings ++ col.warnings;
          info = acc.info ++ col.info;
          hasErrors = acc.hasErrors || col.hasErrors;
          hasWarnings = acc.hasWarnings || col.hasWarnings;
        }) self.collector.new collectors;
      
      # Check if collector has issues
      hasIssues = collector:
        collector.hasErrors || collector.hasWarnings;
    };
    
    # Error reporting formats
    formats = {
      # Terminal output with colors
      terminal = collector:
        let
          errorCount = lib.length collector.errors;
          warningCount = lib.length collector.warnings;
          infoCount = lib.length collector.info;
          
          formatError = error:
            "  ${errors.format.formatError error}";
          
          formatWarning = warning:
            "  ⚠ ${warning}";
          
          formatInfo = info:
            "  ℹ ${info}";
          
          errorSection = lib.optionalString (errorCount > 0) ''
            
            ❌ Errors (${toString errorCount}):
            ${lib.concatStringsSep "\n\n" (map formatError collector.errors)}
          '';
          
          warningSection = lib.optionalString (warningCount > 0) ''
            
            ⚠️  Warnings (${toString warningCount}):
            ${lib.concatStringsSep "\n" (map formatWarning collector.warnings)}
          '';
          
          infoSection = lib.optionalString (infoCount > 0) ''
            
            ℹ️  Information (${toString infoCount}):
            ${lib.concatStringsSep "\n" (map formatInfo collector.info)}
          '';
        in ''
          ╔══════════════════════════════════════════╗
          ║          Configuration Report            ║
          ╚══════════════════════════════════════════╝
          ${errorSection}${warningSection}${infoSection}
          
          Summary: ${toString errorCount} error(s), ${toString warningCount} warning(s)
        '';
      
      # JSON output for tooling
      json = collector:
        builtins.toJSON {
          errors = map (e: {
            inherit (e) type message context suggestions;
          }) collector.errors;
          warnings = collector.warnings;
          info = collector.info;
          summary = {
            errorCount = lib.length collector.errors;
            warningCount = lib.length collector.warnings;
            infoCount = lib.length collector.info;
            hasIssues = collector.hasIssues;
          };
        };
      
      # HTML report
      html = collector:
        let
          errorRows = map (error: ''
            <tr class="error">
              <td>❌</td>
              <td>${error.type}</td>
              <td>${error.message}</td>
              <td>${lib.concatStringsSep "<br>" error.suggestions}</td>
            </tr>
          '') collector.errors;
          
          warningRows = map (warning: ''
            <tr class="warning">
              <td>⚠️</td>
              <td>warning</td>
              <td>${warning}</td>
              <td>-</td>
            </tr>
          '') collector.warnings;
        in ''
          <!DOCTYPE html>
          <html>
          <head>
            <title>Nix Configuration Report</title>
            <style>
              body { font-family: sans-serif; margin: 20px; }
              table { border-collapse: collapse; width: 100%; }
              th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
              th { background-color: #f2f2f2; }
              .error { background-color: #ffebee; }
              .warning { background-color: #fff3cd; }
              .info { background-color: #e3f2fd; }
            </style>
          </head>
          <body>
            <h1>Configuration Report</h1>
            <table>
              <tr>
                <th>Level</th>
                <th>Type</th>
                <th>Message</th>
                <th>Suggestions</th>
              </tr>
              ${lib.concatStringsSep "\n" (errorRows ++ warningRows)}
            </table>
          </body>
          </html>
        '';
    };
    
    # Build-time assertions with error collection
    assertions = {
      # Assert with error collection
      collectAssertions = assertions:
        let
          failed = lib.filter (a: !a.assertion) assertions;
          collector = lib.foldl' (col: a:
            self.collector.addError col (errors.types.configError a.message {
              assertion = toString a.assertion;
            })
          ) self.collector.new failed;
        in
          if failed == [] then
            { success = true; inherit collector; }
          else
            { success = false; inherit collector; };
      
      # Run assertions and report
      runAssertions = assertions:
        let
          result = self.assertions.collectAssertions assertions;
        in
          if result.success then
            true
          else
            throw (self.formats.terminal result.collector);
    };
    
    # Module validation with error reporting
    validation = {
      # Validate module options
      validateModule = module:
        let
          collector = self.collector.new;
          
          # Check for required options
          checkRequired = collector:
            if module ? options then
              lib.foldl' (col: opt:
                if opt.type.check (opt.default or null) then
                  col
                else
                  self.collector.addError col (errors.patterns.optionNotFound opt.name module.name)
              ) collector (lib.attrValues module.options)
            else collector;
          
          # Check for circular dependencies
          checkCircular = collector:
            if module ? imports then
              let
                circular = errors.modules.findCircularDeps module.imports;
              in
                if circular != [] then
                  self.collector.addError collector (errors.patterns.circularDependency circular)
                else collector
            else collector;
          
          finalCollector = checkCircular (checkRequired collector);
        in
          if self.collector.hasErrors finalCollector then
            throw (self.formats.terminal finalCollector)
          else
            module;
    };
    
    # Integration helpers
    integration = {
      # Wrap a module with error handling
      wrapModule = module:
        { config, lib, pkgs, ... }@args:
        let
          wrapped = errors.handlers.tryWithError (module args);
        in
          if wrapped.success then
            wrapped.value
          else
            throw (errors.format.prettyError wrapped.error);
      
      # Add error reporting to system
      addToSystem = {
        # Script to generate error report
        environment.systemPackages = [
          (pkgs.writeScriptBin "nix-errors" ''
            #!${pkgs.bash}/bin/bash
            echo "Checking configuration for errors..."
            
            # This would be populated by the build process
            if [ -f /run/current-system/configuration-report.json ]; then
              ${pkgs.jq}/bin/jq . /run/current-system/configuration-report.json
            else
              echo "No error report found"
            fi
          '')
        ];
        
        # Generate report during build
        system.extraSystemBuilderCmds = ''
          # Generate configuration report
          if [ -n "$configurationReport" ]; then
            cp $configurationReport $out/configuration-report.json
          fi
        '';
      };
    };
    
    # Live error monitoring
    monitoring = {
      # Watch for runtime errors
      watchErrors = {
        services.nix-error-monitor = {
          description = "Nix Error Monitor";
          serviceConfig = {
            Type = "simple";
            ExecStart = pkgs.writeScript "nix-error-monitor" ''
              #!${pkgs.bash}/bin/bash
              
              # Monitor system journal for Nix errors
              ${pkgs.systemd}/bin/journalctl -f -u nixos-rebuild.service |
              while read line; do
                if echo "$line" | grep -E "(error|failed|assertion)" >/dev/null; then
                  echo "[$(date)] Nix error detected: $line" >> /var/log/nix-errors.log
                fi
              done
            '';
            Restart = "always";
          };
        };
      };
      
      # Error dashboard
      dashboard = port: {
        services.nix-error-dashboard = {
          description = "Nix Error Dashboard";
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Type = "simple";
            ExecStart = pkgs.writeScript "error-dashboard" ''
              #!${pkgs.python3}/bin/python3
              import http.server
              import json
              import os
              
              class ErrorHandler(http.server.BaseHTTPRequestHandler):
                  def do_GET(self):
                      if self.path == "/":
                          self.send_response(200)
                          self.send_header("Content-type", "text/html")
                          self.end_headers()
                          
                          with open("/run/current-system/configuration-report.html", "r") as f:
                              self.wfile.write(f.read().encode())
                      else:
                          self.send_error(404)
              
              server = http.server.HTTPServer(('', ${toString port}), ErrorHandler)
              server.serve_forever()
            '';
          };
        };
      };
    };
  };
in self