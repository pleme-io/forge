# Comprehensive error handling library
{ lib }:
let
  self = {
    # Error types
    types = {
      # Create a standard error
      mkError = { type ? "error", message, context ? {}, suggestions ? [] }:
        {
          inherit type message context suggestions;
          timestamp = builtins.currentTime;
          trace = builtins.getEnv "NIX_SHOW_TRACE" == "1";
        };
      
      # Specific error types
      configError = message: context: self.types.mkError {
        type = "config";
        inherit message context;
        suggestions = [
          "Check your configuration syntax"
          "Verify all required options are set"
          "Run 'nixos-option' to inspect values"
        ];
      };
      
      evalError = message: context: self.types.mkError {
        type = "evaluation";
        inherit message context;
        suggestions = [
          "Check for infinite recursion"
          "Verify all imports exist"
          "Use --show-trace for details"
        ];
      };
      
      buildError = message: context: self.types.mkError {
        type = "build";
        inherit message context;
        suggestions = [
          "Check build dependencies"
          "Verify network connectivity"
          "Try with --fallback"
        ];
      };
      
      moduleError = message: context: self.types.mkError {
        type = "module";
        inherit message context;
        suggestions = [
          "Check module imports"
          "Verify option definitions"
          "Look for conflicting modules"
        ];
      };
    };
    
    # Error handling functions
    handlers = {
      # Try-catch pattern
      tryEval = expr: default:
        let
          result = builtins.tryEval expr;
        in
          if result.success then result.value else default;
      
      # Try with error reporting
      tryWithError = expr:
        let
          result = builtins.tryEval expr;
        in
          if result.success then
            { success = true; value = result.value; }
          else
            { 
              success = false; 
              error = self.types.evalError "Expression evaluation failed" {
                expression = toString expr;
              };
            };
      
      # Assert with custom error
      assertWithError = condition: error: expr:
        if condition then expr
        else throw (self.format.formatError error);
      
      # Multiple assertions
      assertAll = assertions: expr:
        let
          failed = lib.filter (a: !a.assertion) assertions;
          errors = map (a: a.message) failed;
        in
          if failed == [] then expr
          else throw (self.format.formatErrors errors);
      
      # Catch specific error types
      catchType = errorType: expr: handler:
        let
          result = builtins.tryEval expr;
        in
          if result.success then result.value
          else if lib.hasInfix errorType (toString result.value) then
            handler result.value
          else throw result.value;
    };
    
    # Error recovery
    recovery = {
      # Provide fallback value
      withFallback = expr: fallback:
        self.handlers.tryEval expr fallback;
      
      # Retry with different parameters
      retry = attempts: delay: expr:
        let
          attempt = n:
            let result = builtins.tryEval expr;
            in if result.success then result.value
               else if n > 1 then attempt (n - 1)
               else throw "All ${toString attempts} attempts failed";
        in attempt attempts;
      
      # Use default on error
      withDefault = default: expr:
        let result = builtins.tryEval expr;
        in if result.success && result.value != null 
           then result.value 
           else default;
      
      # Coerce to valid value
      coerceOrDefault = type: default: value:
        if type.check value then value else default;
    };
    
    # Validation with errors
    validation = {
      # Validate with error
      validate = check: error: value:
        if check value then value
        else throw (self.format.formatError error);
      
      # Validate type
      validateType = type: value:
        self.validation.validate type.check 
          (self.types.mkError {
            type = "type";
            message = "Invalid type";
            context = {
              expected = type.description or "unknown";
              actual = builtins.typeOf value;
              value = toString value;
            };
          }) value;
      
      # Validate options
      validateOption = opt: value:
        let
          typeCheck = opt.type.check value;
          customCheck = opt.check or (v: true);
        in
          if !typeCheck then
            throw "Option type mismatch: expected ${opt.type.description}"
          else if !customCheck value then
            throw "Option validation failed: ${opt.description or "no description"}"
          else
            value;
      
      # Chain validations
      validateChain = validations: value:
        lib.foldl' (v: validation: validation v) value validations;
    };
    
    # Error formatting
    format = {
      # Format single error
      formatError = error:
        let
          header = "[${lib.toUpper error.type}] ${error.message}";
          contextStr = if error.context != {} then
            "\nContext:\n" + lib.concatStringsSep "\n" 
              (lib.mapAttrsToList (k: v: "  ${k}: ${toString v}") error.context)
          else "";
          suggestionsStr = if error.suggestions != [] then
            "\nSuggestions:\n" + lib.concatStringsSep "\n"
              (map (s: "  - ${s}") error.suggestions)
          else "";
        in header + contextStr + suggestionsStr;
      
      # Format multiple errors
      formatErrors = errors:
        let
          count = lib.length errors;
          header = "\nFound ${toString count} error(s):";
          errorList = lib.concatStringsSep "\n\n" 
            (lib.imap1 (i: e: "${toString i}. ${self.format.formatError e}") errors);
        in header + "\n\n" + errorList;
      
      # Pretty print for debugging
      prettyError = error:
        let
          indent = level: lib.concatStrings (lib.genList (x: "  ") level);
          formatValue = level: value:
            if lib.isAttrs value then
              "{\n" + lib.concatStringsSep "\n" 
                (lib.mapAttrsToList (k: v: 
                  "${indent (level + 1)}${k} = ${formatValue (level + 1) v};") value) +
              "\n${indent level}}"
            else if lib.isList value then
              "[ " + lib.concatStringsSep " " (map (formatValue level) value) + " ]"
            else
              toString value;
        in ''
          ╭─ Error Report ──────────────────────
          │ Type: ${error.type}
          │ Time: ${toString error.timestamp}
          │ Message: ${error.message}
          ${if error.context != {} then "│\n│ Context:\n" + 
            lib.concatStringsSep "\n" (lib.mapAttrsToList 
              (k: v: "│   ${k}: ${formatValue 2 v}") error.context) else ""}
          ${if error.suggestions != [] then "│\n│ Suggestions:\n" +
            lib.concatStringsSep "\n" (map (s: "│   • ${s}") error.suggestions) else ""}
          ╰─────────────────────────────────────
        '';
    };
    
    # Debugging utilities
    debug = {
      # Trace with context
      traceContext = context: value:
        builtins.trace "Context: ${self.format.formatValue context}" value;
      
      # Conditional trace
      traceIf = condition: message: value:
        if condition then builtins.trace message value else value;
      
      # Trace call stack
      traceCall = name: args: result:
        let
          argsStr = self.format.formatValue args;
          resultStr = self.format.formatValue result;
        in
          builtins.trace "Call: ${name}(${argsStr}) = ${resultStr}" result;
      
      # Assert with trace
      assertTrace = condition: message: value:
        if condition then value
        else builtins.trace "Assertion failed: ${message}" 
          (throw "Assertion failed: ${message}");
      
      # Debug break
      breakpoint = message: value:
        if builtins.getEnv "NIX_DEBUG" == "1" then
          builtins.trace "BREAKPOINT: ${message}" 
            (builtins.trace "Value: ${self.format.formatValue value}" value)
        else value;
    };
    
    # Error collection
    collect = {
      # Collect errors without throwing
      collectErrors = exprs:
        let
          results = map (expr: builtins.tryEval expr) exprs;
          errors = lib.filter (r: !r.success) results;
          values = map (r: r.value) (lib.filter (r: r.success) results);
        in {
          success = errors == [];
          inherit values errors;
        };
      
      # Validate all with collection
      validateAll = validations:
        let
          results = self.collect.collectErrors validations;
        in
          if results.success then true
          else throw (self.format.formatErrors results.errors);
      
      # Map with error collection
      mapSafe = f: list:
        let
          results = map (x: self.handlers.tryWithError (f x)) list;
          errors = lib.filter (r: !r.success) results;
          values = map (r: r.value) (lib.filter (r: r.success) results);
        in
          if errors == [] then values
          else throw "Errors in mapSafe:\n" + 
            lib.concatStringsSep "\n" (map (e: self.format.formatError e.error) errors);
    };
    
    # Common error patterns
    patterns = {
      # Option not found
      optionNotFound = option: path:
        self.types.configError "Option '${option}' not found" {
          path = toString path;
          availableOptions = "Run 'nixos-option ${option}' to see available options";
        };
      
      # Type mismatch
      typeMismatch = expected: actual: value:
        self.types.mkError {
          type = "type";
          message = "Type mismatch";
          context = {
            inherit expected actual;
            value = self.format.formatValue value;
          };
          suggestions = [
            "Check the option type definition"
            "Convert the value to ${expected}"
          ];
        };
      
      # Missing dependency
      missingDependency = dep: context:
        self.types.buildError "Missing dependency: ${dep}" {
          inherit context;
          dependency = dep;
        };
      
      # Circular dependency
      circularDependency = path:
        self.types.moduleError "Circular dependency detected" {
          path = lib.concatStringsSep " -> " path;
        };
    };
    
    # Helper to format values safely
    format.formatValue = value:
      if lib.isString value then value
      else if lib.isInt value then toString value
      else if lib.isBool value then if value then "true" else "false"
      else if lib.isList value then 
        "[ " + lib.concatStringsSep " " (map self.format.formatValue value) + " ]"
      else if lib.isAttrs value then
        "{ " + lib.concatStringsSep " " 
          (lib.mapAttrsToList (k: v: "${k} = ${self.format.formatValue v};") value) + " }"
      else "<complex value>";
  };
in self