# Performance monitoring and optimization library
{ lib, pkgs ? null }:
let
  self = {
    # Metrics collection
    metrics = {
      # Create a metric entry
      mkMetric = { name, value, unit ? "", timestamp ? null, tags ? {} }:
        {
          inherit name value unit tags;
          timestamp = if timestamp != null then timestamp else builtins.currentTime;
        };
      
      # Aggregate metrics
      aggregate = metrics: operation:
        let
          values = map (m: m.value) metrics;
        in
          if operation == "sum" then lib.foldl' (a: b: a + b) 0 values
          else if operation == "avg" then (lib.foldl' (a: b: a + b) 0 values) / (lib.length values)
          else if operation == "max" then lib.foldl' (a: b: if a > b then a else b) (lib.head values) values
          else if operation == "min" then lib.foldl' (a: b: if a < b then a else b) (lib.head values) values
          else throw "Unknown aggregation operation: ${operation}";
      
      # Group metrics by tag
      groupByTag = metrics: tagName:
        lib.groupBy (m: m.tags.${tagName} or "unknown") metrics;
    };
    
    # Build performance tracking
    build = {
      # Track build timing
      timeCommand = command:
        let
          startTime = builtins.currentTime;
          result = command;
          endTime = builtins.currentTime;
          duration = endTime - startTime;
        in {
          inherit result duration;
          metric = self.metrics.mkMetric {
            name = "build_duration";
            value = duration;
            unit = "seconds";
          };
        };
      
      # Measure derivation size
      measureDerivation = drv:
        let
          closureInfo = pkgs.closureInfo { rootPaths = [ drv ]; };
          size = builtins.readFile "${closureInfo}/closure-size";
        in self.metrics.mkMetric {
          name = "derivation_size";
          value = lib.toInt size;
          unit = "bytes";
          tags = { derivation = drv.name or "unknown"; };
        };
      
      # Count dependencies
      countDependencies = drv:
        let
          closure = pkgs.closureInfo { rootPaths = [ drv ]; };
          storePathsFile = "${closure}/store-paths";
          storePaths = lib.splitString "\n" (builtins.readFile storePathsFile);
          depCount = lib.length (lib.filter (p: p != "") storePaths) - 1;
        in self.metrics.mkMetric {
          name = "dependency_count";
          value = depCount;
          unit = "dependencies";
          tags = { derivation = drv.name or "unknown"; };
        };
    };
    
    # Evaluation performance
    evaluation = {
      # Profile expression evaluation
      profile = expr:
        let
          startTime = builtins.currentTime;
          startMem = builtins.tryEval (builtins.deepSeq expr true);
          result = builtins.deepSeq expr expr;
          endTime = builtins.currentTime;
          duration = endTime - startTime;
        in {
          inherit result duration;
          metric = self.metrics.mkMetric {
            name = "eval_duration";
            value = duration;
            unit = "seconds";
          };
        };
      
      # Measure attribute set size
      measureAttrSet = attrs:
        let
          count = lib.length (lib.attrNames attrs);
          deepCount = lib.foldl' (acc: val:
            acc + (if lib.isAttrs val then self.evaluation.measureAttrSet val else 0)
          ) count (lib.attrValues attrs);
        in {
          shallow = count;
          deep = deepCount;
          metric = self.metrics.mkMetric {
            name = "attrset_size";
            value = deepCount;
            unit = "attributes";
          };
        };
      
      # Check for expensive operations
      findExpensiveOps = expr:
        let
          checkExpr = e:
            if lib.isFunction e then
              { type = "function"; expensive = false; }
            else if lib.isAttrs e then
              let subChecks = lib.mapAttrs (n: checkExpr) e;
              in {
                type = "attrs";
                expensive = lib.any (x: x.expensive or false) (lib.attrValues subChecks);
                details = lib.filterAttrs (n: v: v.expensive or false) subChecks;
              }
            else if lib.isList e then
              let
                listLength = lib.length e;
                expensive = listLength > 1000;
              in {
                type = "list";
                inherit expensive;
                length = listLength;
              }
            else
              { type = "other"; expensive = false; };
        in checkExpr expr;
    };
    
    # Module performance
    modules = {
      # Analyze module complexity
      analyzeModule = module:
        let
          options = module.options or {};
          config = module.config or {};
          imports = module.imports or [];
          
          optionCount = self.evaluation.measureAttrSet options;
          configSize = self.evaluation.measureAttrSet config;
          importCount = lib.length imports;
        in {
          inherit optionCount configSize importCount;
          complexity = optionCount.deep + configSize.deep + (importCount * 10);
          metrics = [
            (self.metrics.mkMetric {
              name = "module_options";
              value = optionCount.deep;
              unit = "options";
            })
            (self.metrics.mkMetric {
              name = "module_config_size";
              value = configSize.deep;
              unit = "attributes";
            })
            (self.metrics.mkMetric {
              name = "module_imports";
              value = importCount;
              unit = "imports";
            })
          ];
        };
      
      # Find circular dependencies
      findCircularDeps = modules:
        let
          getImports = mod: mod.imports or [];
          
          checkCircular = visited: current:
            if lib.elem current visited then
              { circular = true; path = visited ++ [ current ]; }
            else
              let
                newVisited = visited ++ [ current ];
                imports = getImports current;
                checks = map (checkCircular newVisited) imports;
                circular = lib.any (c: c.circular) checks;
                firstCircular = lib.findFirst (c: c.circular) null checks;
              in
                if circular then firstCircular
                else { circular = false; };
        in lib.mapAttrs (name: mod: checkCircular [] mod) modules;
    };
    
    # Optimization helpers
    optimization = {
      # Lazy evaluation wrapper
      makeLazy = expr:
        let lazy = expr; in lazy;
      
      # Memoization helper
      memoize = f:
        let
          cache = {};
          memoized = x:
            if cache ? ${toString x} then
              cache.${toString x}
            else
              let result = f x;
              in builtins.seq (cache.${toString x} = result) result;
        in memoized;
      
      # Parallel evaluation hint
      parallel = exprs:
        map (e: builtins.deepSeq e e) exprs;
      
      # Chunking for large lists
      chunk = size: list:
        let
          len = lib.length list;
          chunks = lib.genList (i:
            let
              start = i * size;
              end = lib.min ((i + 1) * size) len;
            in lib.sublist start (end - start) list
          ) ((len + size - 1) / size);
        in chunks;
    };
    
    # Performance recommendations
    recommendations = {
      # Check for common issues
      analyze = config:
        let
          issues = [];
          
          # Check for large lists
          largeListCheck = 
            if lib.any (x: lib.isList x && lib.length x > 1000) (lib.attrValues config) then
              issues ++ ["Large lists detected (>1000 items) - consider chunking"]
            else issues;
          
          # Check for deep recursion
          deepRecursionCheck =
            let depth = self.evaluation.measureAttrSet config;
            in if depth.deep > 10000 then
              issues ++ ["Deep attribute structure (${toString depth.deep} attrs) - consider flattening"]
            else issues;
          
          # Check module count
          moduleCountCheck =
            let moduleCount = lib.length (config.imports or []);
            in if moduleCount > 100 then
              issues ++ ["Many module imports (${toString moduleCount}) - consider consolidation"]
            else issues;
            
        in lib.foldl' (acc: check: check) issues [
          largeListCheck
          deepRecursionCheck
          moduleCountCheck
        ];
      
      # Generate optimization report
      report = metrics:
        let
          grouped = self.metrics.groupByTag metrics "name";
          summaries = lib.mapAttrs (name: ms:
            let
              values = map (m: m.value) ms;
              avg = self.metrics.aggregate ms "avg";
              max = self.metrics.aggregate ms "max";
              min = self.metrics.aggregate ms "min";
            in {
              count = lib.length ms;
              inherit avg max min;
            }
          ) grouped;
        in ''
          # Performance Report
          
          ## Metrics Summary
          ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: summary: ''
          
          ### ${name}
          - Count: ${toString summary.count}
          - Average: ${toString summary.avg}
          - Max: ${toString summary.max}
          - Min: ${toString summary.min}
          '') summaries)}
          
          ## Recommendations
          ${lib.concatStringsSep "\n" (map (r: "- ${r}") (self.recommendations.analyze {}))}
        '';
    };
  };
in self