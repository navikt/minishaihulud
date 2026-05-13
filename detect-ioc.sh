#!/usr/bin/env bash
#
# Mini Shai-Hulud Detector (May 2026 Variant)
# Detects IOCs from the TanStack / npm supply chain compromise wave
# Source: https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
#
# Usage: ./detect-mini-shai-hulud.sh [DIRECTORY]
#   DIRECTORY defaults to ~/dev if not provided
#
# This script is READ-ONLY. It does not modify, delete, or execute any files.
#
#
#Copied from https://gist.github.com/Capevace/8eb82102557d76bb15858f12dd67788b

set -euo pipefail

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Affected packages with exact versions (from Aikido blog, May 12 2026)
# Format: "name:version"
# ---------------------------------------------------------------------------
COMPROMISED_PACKAGES=(
  "@tanstack/history:1.161.9"
  "@tanstack/history:1.161.12"
  "@tanstack/react-router:1.169.5"
  "@tanstack/react-router:1.169.8"
  "@tanstack/router-core:1.169.5"
  "@tanstack/router-core:1.169.8"
  "@tanstack/router-utils:1.161.11"
  "@tanstack/router-utils:1.161.14"
  "@tanstack/router-plugin:1.167.38"
  "@tanstack/router-plugin:1.167.41"
  "@tanstack/virtual-file-routes:1.161.10"
  "@tanstack/virtual-file-routes:1.161.13"
  "@tanstack/router-generator:1.166.45"
  "@tanstack/router-generator:1.166.48"
  "@tanstack/start-server-core:1.167.33"
  "@tanstack/start-server-core:1.167.36"
  "@tanstack/start-client-core:1.168.5"
  "@tanstack/start-client-core:1.168.8"
  "@tanstack/start-storage-context:1.166.38"
  "@tanstack/start-storage-context:1.166.41"
  "@tanstack/start-plugin-core:1.169.23"
  "@tanstack/start-plugin-core:1.169.26"
  "@tanstack/react-start-server:1.166.55"
  "@tanstack/react-start-server:1.166.58"
  "@tanstack/react-start-client:1.166.51"
  "@tanstack/react-start-client:1.166.54"
  "@tanstack/start-fn-stubs:1.161.9"
  "@tanstack/start-fn-stubs:1.161.12"
  "@tanstack/react-start:1.167.68"
  "@tanstack/react-start:1.167.71"
  "@tanstack/react-start-rsc:0.0.47"
  "@tanstack/react-start-rsc:0.0.50"
  "@mistralai/mistralai:2.2.2"
  "@mistralai/mistralai:2.2.3"
  "@mistralai/mistralai:2.2.4"
  "@tanstack/react-router-devtools:1.166.16"
  "@tanstack/react-router-devtools:1.166.19"
  "@tanstack/router-devtools-core:1.167.6"
  "@tanstack/router-devtools-core:1.167.9"
  "@tanstack/router-devtools:1.166.16"
  "@tanstack/router-devtools:1.166.19"
  "@tanstack/router-ssr-query-core:1.168.3"
  "@tanstack/router-ssr-query-core:1.168.6"
  "@tanstack/react-router-ssr-query:1.166.15"
  "@tanstack/react-router-ssr-query:1.166.18"
  "@tanstack/router-cli:1.166.46"
  "@tanstack/router-cli:1.166.49"
  "@tanstack/zod-adapter:1.166.12"
  "@tanstack/zod-adapter:1.166.15"
  "@tanstack/eslint-plugin-router:1.161.9"
  "@tanstack/router-vite-plugin:1.166.53"
  "@tanstack/router-vite-plugin:1.166.56"
  "@tanstack/nitro-v2-vite-plugin:1.154.12"
  "@tanstack/nitro-v2-vite-plugin:1.154.15"
  "@mistralai/mistralai-gcp:1.7.1"
  "@mistralai/mistralai-gcp:1.7.2"
  "@mistralai/mistralai-gcp:1.7.3"
  "@tanstack/solid-router:1.169.5"
  "@tanstack/solid-router:1.169.8"
  "@tanstack/solid-start:1.167.65"
  "@tanstack/solid-start:1.167.68"
  "@tanstack/solid-start-client:1.166.50"
  "@tanstack/solid-start-client:1.166.53"
  "@tanstack/solid-start-server:1.166.54"
  "@tanstack/solid-start-server:1.166.57"
  "@tanstack/solid-router-devtools:1.166.16"
  "@tanstack/solid-router-devtools:1.166.19"
  "@tanstack/start-static-server-functions:1.166.44"
  "@tanstack/start-static-server-functions:1.166.47"
  "@tanstack/vue-router:1.169.5"
  "@tanstack/vue-router:1.169.8"
  "@uipath/apollo-react:4.24.5"
  "@tanstack/solid-router-ssr-query:1.166.15"
  "@tanstack/solid-router-ssr-query:1.166.18"
  "safe-action:0.8.3"
  "safe-action:0.8.4"
  "@tanstack/valibot-adapter:1.166.12"
  "@tanstack/valibot-adapter:1.166.15"
  "@uipath/apollo-wind:2.16.2"
  "@uipath/cli:1.0.1"
  "@tanstack/vue-start:1.167.61"
  "@tanstack/vue-start:1.167.64"
  "@uipath/rpa-tool:0.9.5"
  "@squawk/types:0.8.2"
  "@squawk/types:0.8.3"
  "@squawk/types:0.8.4"
  "@uipath/mcp:0.9.1"
  "@uipath/mcp:0.9.2"
  "@uipath/mcp:0.9.3"
  "@uipath/mcp:0.9.4"
  "@squawk/weather:0.5.6"
  "@squawk/weather:0.5.7"
  "@squawk/weather:0.5.8"
  "@squawk/weather:0.5.9"
  "@squawk/airspace:0.8.1"
  "@squawk/airspace:0.8.2"
  "@squawk/airspace:0.8.3"
  "@squawk/airspace:0.8.4"
  "@squawk/icao-registry-data:0.8.4"
  "@squawk/icao-registry-data:0.8.5"
  "@squawk/icao-registry-data:0.8.6"
  "@squawk/icao-registry-data:0.8.7"
  "@tanstack/arktype-adapter:1.166.12"
  "@tanstack/arktype-adapter:1.166.15"
  "@squawk/flightplan:0.5.2"
  "@squawk/flightplan:0.5.3"
  "@squawk/flightplan:0.5.4"
  "@squawk/flightplan:0.5.5"
  "@squawk/airports:0.6.2"
  "@squawk/airports:0.6.3"
  "@squawk/airports:0.6.4"
  "@squawk/airports:0.6.5"
  "@mesadev/sdk:0.28.3"
  "@squawk/geo:0.4.4"
  "@squawk/geo:0.4.5"
  "@squawk/geo:0.4.6"
  "@squawk/geo:0.4.7"
  "@mesadev/rest:0.28.3"
  "@squawk/procedure-data:0.7.3"
  "@squawk/procedure-data:0.7.4"
  "@squawk/procedure-data:0.7.5"
  "@squawk/procedure-data:0.7.6"
  "@squawk/navaid-data:0.6.4"
  "@squawk/navaid-data:0.6.5"
  "@squawk/navaid-data:0.6.6"
  "@squawk/navaid-data:0.6.7"
  "@squawk/fix-data:0.6.4"
  "@squawk/fix-data:0.6.5"
  "@squawk/fix-data:0.6.6"
  "@squawk/fix-data:0.6.7"
  "@squawk/navaids:0.4.2"
  "@squawk/navaids:0.4.3"
  "@squawk/navaids:0.4.4"
  "@squawk/navaids:0.4.5"
  "@squawk/fixes:0.3.2"
  "@squawk/fixes:0.3.3"
  "@squawk/fixes:0.3.4"
  "@squawk/fixes:0.3.5"
  "@squawk/airport-data:0.7.4"
  "@squawk/airport-data:0.7.5"
  "@squawk/airport-data:0.7.6"
  "@squawk/airport-data:0.7.7"
  "@squawk/airway-data:0.5.4"
  "@squawk/airway-data:0.5.5"
  "@squawk/airway-data:0.5.6"
  "@squawk/airway-data:0.5.7"
  "@squawk/units:0.4.3"
  "@squawk/units:0.4.4"
  "@squawk/units:0.4.5"
  "@squawk/units:0.4.6"
  "@squawk/procedures:0.5.2"
  "@squawk/procedures:0.5.3"
  "@squawk/procedures:0.5.4"
  "@squawk/procedures:0.5.5"
  "@squawk/airways:0.4.2"
  "@squawk/airways:0.4.3"
  "@squawk/airways:0.4.4"
  "@squawk/airways:0.4.5"
  "@squawk/icao-registry:0.5.2"
  "@squawk/icao-registry:0.5.3"
  "@squawk/icao-registry:0.5.4"
  "@squawk/icao-registry:0.5.5"
  "@uipath/apollo-core:5.9.2"
  "@squawk/notams:0.3.6"
  "@squawk/notams:0.3.7"
  "@squawk/notams:0.3.8"
  "@squawk/notams:0.3.9"
  "@uipath/filesystem:1.0.1"
  "@uipath/solutionpackager-tool-core:0.0.34"
  "@squawk/flight-math:0.5.4"
  "@squawk/flight-math:0.5.5"
  "@squawk/flight-math:0.5.6"
  "@squawk/flight-math:0.5.7"
  "@squawk/airspace-data:0.5.3"
  "@squawk/airspace-data:0.5.4"
  "@squawk/airspace-data:0.5.5"
  "@squawk/airspace-data:0.5.6"
  "@mistralai/mistralai-azure:1.7.1"
  "@mistralai/mistralai-azure:1.7.2"
  "@mistralai/mistralai-azure:1.7.3"
  "@uipath/solution-tool:1.0.1"
  "@uipath/packager-tool-bpmn:0.0.9"
  "@draftlab/auth:0.24.1"
  "@draftlab/auth:0.24.2"
  "@uipath/maestro-tool:1.0.1"
  "@uipath/codedapp-tool:1.0.1"
  "@uipath/agent-tool:1.0.1"
  "@uipath/orchestrator-tool:1.0.1"
  "@uipath/integrationservice-tool:1.0.2"
  "@taskflow-corp/cli:0.1.24"
  "@taskflow-corp/cli:0.1.25"
  "@taskflow-corp/cli:0.1.26"
  "@taskflow-corp/cli:0.1.27"
  "@taskflow-corp/cli:0.1.28"
  "@taskflow-corp/cli:0.1.29"
  "@tanstack/vue-router-ssr-query:1.166.15"
  "@tanstack/vue-router-ssr-query:1.166.18"
  "@uipath/rpa-legacy-tool:1.0.1"
  "@uipath/vertical-solutions-tool:1.0.1"
  "@uipath/flow-tool:1.0.2"
  "@uipath/codedagent-tool:1.0.1"
  "@uipath/common:1.0.1"
  "@uipath/resource-tool:1.0.1"
  "@uipath/auth:1.0.1"
  "@uipath/docsai-tool:1.0.1"
  "@uipath/case-tool:1.0.1"
  "@uipath/api-workflow-tool:1.0.1"
  "@tanstack/vue-router-devtools:1.166.16"
  "@tanstack/vue-router-devtools:1.166.19"
  "@uipath/test-manager-tool:1.0.2"
  "@uipath/robot:1.3.4"
  "@uipath/traces-tool:1.0.1"
  "@uipath/agent-sdk:1.0.2"
  "@uipath/integrationservice-sdk:1.0.2"
  "@uipath/maestro-sdk:1.0.1"
  "@uipath/data-fabric-tool:1.0.2"
  "@mesadev/saguaro:0.4.22"
  "@uipath/tasks-tool:1.0.1"
  "@uipath/insights-tool:1.0.1"
  "@uipath/insights-sdk:1.0.1"
  "@uipath/uipath-python-bridge:1.0.1"
  "@draftlab/db:0.16.1"
  "@uipath/ap-chat:1.5.7"
  "@uipath/project-packager:1.1.16"
  "@uipath/packager-tool-case:0.0.9"
  "@uipath/packager-tool-workflowcompiler-browser:0.0.34"
  "@uipath/packager-tool-connector:0.0.19"
  "@uipath/packager-tool-workflowcompiler:0.0.16"
  "@uipath/packager-tool-webapp:1.0.6"
  "@uipath/packager-tool-apiworkflow:0.0.19"
  "@uipath/packager-tool-functions:0.1.1"
  "ts-dna:3.0.1"
  "ts-dna:3.0.2"
  "ts-dna:3.0.3"
  "ts-dna:3.0.4"
  "@uipath/widget.sdk:1.2.3"
  "@uipath/resources-tool:0.1.11"
  "@uipath/agent.sdk:0.0.18"
  "cross-stitch:1.1.3"
  "cross-stitch:1.1.4"
  "cross-stitch:1.1.5"
  "cross-stitch:1.1.6"
  "@uipath/codedagents-tool:0.1.12"
  "@uipath/aops-policy-tool:0.3.1"
  "@uipath/solution-packager:0.0.35"
  "@draftlab/auth-router:0.5.1"
  "@draftlab/auth-router:0.5.2"
  "cmux-agent-mcp:0.1.3"
  "cmux-agent-mcp:0.1.4"
  "cmux-agent-mcp:0.1.5"
  "cmux-agent-mcp:0.1.6"
  "cmux-agent-mcp:0.1.7"
  "cmux-agent-mcp:0.1.8"
  "agentwork-cli:0.1.4"
  "agentwork-cli:0.1.5"
  "@uipath/packager-tool-flow:0.0.19"
  "@draftauth/core:0.13.1"
  "@draftauth/core:0.13.2"
  "@dirigible-ai/sdk:0.6.2"
  "@dirigible-ai/sdk:0.6.3"
  "git-branch-selector:1.3.3"
  "git-branch-selector:1.3.4"
  "git-branch-selector:1.3.5"
  "git-branch-selector:1.3.6"
  "git-branch-selector:1.3.7"
  "wot-api:0.8.1"
  "wot-api:0.8.2"
  "wot-api:0.8.3"
  "wot-api:0.8.4"
  "git-git-git:1.0.8"
  "git-git-git:1.0.9"
  "git-git-git:1.0.10"
  "git-git-git:1.0.11"
  "git-git-git:1.0.12"
  "@beproduct/nestjs-auth:0.1.2"
  "@beproduct/nestjs-auth:0.1.3"
  "@beproduct/nestjs-auth:0.1.4"
  "@beproduct/nestjs-auth:0.1.5"
  "@beproduct/nestjs-auth:0.1.6"
  "@beproduct/nestjs-auth:0.1.7"
  "@beproduct/nestjs-auth:0.1.8"
  "@beproduct/nestjs-auth:0.1.9"
  "@beproduct/nestjs-auth:0.1.10"
  "@beproduct/nestjs-auth:0.1.11"
  "@beproduct/nestjs-auth:0.1.12"
  "@beproduct/nestjs-auth:0.1.13"
  "@beproduct/nestjs-auth:0.1.14"
  "@beproduct/nestjs-auth:0.1.15"
  "@beproduct/nestjs-auth:0.1.16"
  "@beproduct/nestjs-auth:0.1.17"
  "@beproduct/nestjs-auth:0.1.18"
  "@beproduct/nestjs-auth:0.1.19"
  "@ml-toolkit-ts/xgboost:1.0.3"
  "@ml-toolkit-ts/xgboost:1.0.4"
  "nextmove-mcp:0.1.3"
  "nextmove-mcp:0.1.4"
  "nextmove-mcp:0.1.5"
  "nextmove-mcp:0.1.6"
  "nextmove-mcp:0.1.7"
  "ml-toolkit-ts:1.0.4"
  "ml-toolkit-ts:1.0.5"
  "@uipath/telemetry:0.0.7"
  "@draftauth/client:0.2.1"
  "@draftauth/client:0.2.2"
  "@ml-toolkit-ts/preprocessing:1.0.2"
  "@ml-toolkit-ts/preprocessing:1.0.3"
  "@tallyui/connector-medusa:1.0.1"
  "@tallyui/connector-medusa:1.0.2"
  "@tallyui/connector-medusa:1.0.3"
  "@uipath/tool-workflowcompiler:0.0.12"
  "@uipath/vss:0.1.6"
  "@tallyui/theme:0.2.1"
  "@tallyui/theme:0.2.2"
  "@tallyui/theme:0.2.3"
  "@tallyui/storage-sqlite:0.2.1"
  "@tallyui/storage-sqlite:0.2.2"
  "@tallyui/storage-sqlite:0.2.3"
  "@uipath/solutionpackager-sdk:1.0.11"
  "@tallyui/connector-vendure:1.0.1"
  "@tallyui/connector-vendure:1.0.2"
  "@tallyui/connector-vendure:1.0.3"
  "@tallyui/core:0.2.1"
  "@tallyui/core:0.2.2"
  "@tallyui/core:0.2.3"
  "@tallyui/connector-woocommerce:1.0.1"
  "@tallyui/connector-woocommerce:1.0.2"
  "@tallyui/connector-woocommerce:1.0.3"
  "@tallyui/components:1.0.1"
  "@tallyui/components:1.0.2"
  "@tallyui/components:1.0.3"
  "@uipath/ui-widgets-multi-file-upload:1.0.1"
  "@tallyui/pos:0.1.1"
  "@tallyui/pos:0.1.2"
  "@tallyui/pos:0.1.3"
  "@tallyui/database:1.0.1"
  "@tallyui/database:1.0.2"
  "@tallyui/database:1.0.3"
  "@supersurkhet/cli:0.0.2"
  "@supersurkhet/cli:0.0.3"
  "@supersurkhet/cli:0.0.4"
  "@supersurkhet/cli:0.0.5"
  "@supersurkhet/cli:0.0.6"
  "@supersurkhet/cli:0.0.7"
  "@tallyui/connector-shopify:1.0.1"
  "@tallyui/connector-shopify:1.0.2"
  "@tallyui/connector-shopify:1.0.3"
  "@tolka/cli:1.0.2"
  "@tolka/cli:1.0.3"
  "@tolka/cli:1.0.4"
  "@tolka/cli:1.0.5"
  "@tolka/cli:1.0.6"
  "@supersurkhet/sdk:0.0.2"
  "@supersurkhet/sdk:0.0.3"
  "@supersurkhet/sdk:0.0.4"
  "@supersurkhet/sdk:0.0.5"
  "@supersurkhet/sdk:0.0.6"
  "@supersurkhet/sdk:0.0.7"
  "@uipath/access-policy-tool:0.3.1"
  "@uipath/context-grounding-tool:0.1.1"
  "@uipath/gov-tool:0.3.1"
  "@uipath/admin-tool:0.1.1"
  "@uipath/identity-tool:0.1.1"
  "@uipath/llmgw-tool:1.0.1"
  "@uipath/resourcecatalog-tool:0.1.1"
  "@uipath/functions-tool:1.0.1"
  "@uipath/access-policy-sdk:0.3.1"
  "@uipath/platform-tool:1.0.1"
)

# Compromised namespaces (any package in these namespaces should be flagged for review)
COMPROMISED_NAMESPACES=(
  "@squawk"
  "@tanstack"
  "@uipath"
  "@tallyui"
  "@beproduct"
  "@mistralai"
  "@draftlab"
  "@draftauth"
  "@taskflow-corp"
  "@tolka"
  "@ml-toolkit-ts"
  "@mesadev"
  "@dirigible-ai"
  "@supersurkhet"
)

# Known malicious file hashes
MALICIOUS_HASHES=(
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"   # router_init.js
  "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"   # tanstack_runner.js
)

# Known malicious filenames
PAYLOAD_FILENAMES=(
  "router_init.js"
  "router_runtime.js"
  "tanstack_runner.js"
)

# Known dependency strings / markers
DEPENDENCY_MARKERS=(
  "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
  "@tanstack/setup"
  "bun run tanstack_runner.js"
)

# Network / service indicators (defanged as in blog, and real forms)
NETWORK_INDICATORS=(
  "filev2.getsession.org"
  "169.254.169.254"
  "169.254.170.2"
  "registry.npmjs.org/-/npm/v1/tokens"
  "vault.svc.cluster.local:8200"
  "getsession.org"
)

# Campaign markers
CAMPAIGN_MARKERS=(
  "A Mini Shai-Hulud has Appeared"
)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

print_status() {
  local color=$1; local msg=$2
  echo -e "${color}${msg}${NC}"
}

usage() {
  echo "Usage: $0 [DIRECTORY]"
  echo "  DIRECTORY  Path to scan (default: ~/dev)"
  exit 1
}

# Build associative array for O(1) exact package:version lookups
declare -A BAD_PKG_MAP
declare -A BAD_NS_MAP

load_lookup_tables() {
  for pkg in "${COMPROMISED_PACKAGES[@]}"; do
    BAD_PKG_MAP["$pkg"]=1
  done
  for ns in "${COMPROMISED_NAMESPACES[@]}"; do
    BAD_NS_MAP["$ns"]=1
  done
}

# ---------------------------------------------------------------------------
# Scan stages
# ---------------------------------------------------------------------------

scan_package_json() {
  local scan_dir=$1
  print_status "$BLUE" "[Stage 1/5] Scanning package.json / lockfiles for compromised packages..."

  local pkg_count=0
  local ns_count=0

  # Find all package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
  local files_found=0
  while IFS= read -r -d '' file; do
    files_found=$((files_found + 1))

    # Skip node_modules for performance unless explicitly scanning node_modules
    [[ "$file" == */node_modules/* ]] && continue

    # --- Exact version matching ---
    # Fast path: read the file and grep for known package names, then verify versions
    local file_content
    file_content=$(cat "$file" 2>/dev/null || true)
    [[ -z "$file_content" ]] && continue

    for pkgver in "${COMPROMISED_PACKAGES[@]}"; do
      # package-lock uses "name": "version" with quotes; package.json uses "name": "^version" etc.
      # We search for the raw package name and then inspect context for the version
      local pkg_name="${pkgver%:*}"
      local pkg_ver="${pkgver#*:}"

      if [[ "$file_content" == *"$pkg_name"* ]]; then
        # More precise check: look for version string near the package name
        # This is a heuristic to reduce false positives on large lockfiles
        if grep -qF "\"$pkg_ver\"" <<< "$file_content" 2>/dev/null || \
           grep -qE "${pkg_name}[@ :]${pkg_ver}([\"']|,|\s|\})" <<< "$file_content" 2>/dev/null || \
           grep -qE "\"${pkg_name}\".*\"${pkg_ver}\"" <<< "$file_content" 2>/dev/null; then
          echo "HIGH|$file|$pkgver"
          pkg_count=$((pkg_count + 1))
        fi
      fi
    done

    # --- Namespace matching ---
    for ns in "${COMPROMISED_NAMESPACES[@]}"; do
      # Check if namespace appears in this file (but isn't an exact match already caught above)
      if [[ "$file_content" == *"$ns/"* ]]; then
        # Only report if we didn't already report an exact version match for this namespace
        # Extract matching lines for context
        local matches
        matches=$(grep -o "${ns}/[^\"'\s,>@:]+" <<< "$file_content" 2>/dev/null | sort -u || true)
        if [[ -n "$matches" ]]; then
          while IFS= read -r matched_pkg; do
            # Skip if exact version already reported (simple dedup: check if any version of this pkg was flagged)
            # For reporting, we just list the namespace hit once per file
            : # no-op for dedup complexity - we report namespace hits separately
          done <<< "$matches"
          echo "MED|$file|Namespace $ns detected (review all packages)"
          ns_count=$((ns_count + 1))
          break  # one namespace warning per file is enough
        fi
      fi
    done

  done < <(find "$scan_dir" -type f \( \
    -name "package.json" -o \
    -name "package-lock.json" -o \
    -name "yarn.lock" -o \
    -name "pnpm-lock.yaml" \
  \) -print0 2>/dev/null || true)

  print_status "$BLUE" "   Scanned $files_found lock/package files."
  if [[ $pkg_count -gt 0 ]]; then
    print_status "$RED" "   -> Found $pkg_count exact compromised package:version match(es)."
  fi
  if [[ $ns_count -gt 0 ]]; then
    print_status "$YELLOW" "   -> Found $ns_count file(s) containing compromised namespace(s)."
  fi
}

scan_payload_files() {
  local scan_dir=$1
  print_status "$BLUE" "[Stage 2/5] Scanning for known malicious payload filenames..."

  local found=0
  while IFS= read -r -d '' file; do
    local basename
    basename=$(basename "$file")
    for payload in "${PAYLOAD_FILENAMES[@]}"; do
      if [[ "$basename" == "$payload" ]]; then
        echo "HIGH|$file|Known payload file: $payload"
        found=$((found + 1))

        # Hash check if possible
        local hash=""
        if command -v sha256sum >/dev/null 2>&1; then
          hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
        elif command -v shasum >/dev/null 2>&1; then
          hash=$(shasum -a 256 "$file" 2>/dev/null | awk '{print $1}')
        fi

        if [[ -n "$hash" ]]; then
          for known_hash in "${MALICIOUS_HASHES[@]}"; do
            if [[ "$hash" == "$known_hash" ]]; then
              echo "CRIT|$file|HASH MATCH $hash"
            fi
          done
        fi
      fi
    done
  done < <(find "$scan_dir" -type f \( \
    -name "router_init.js" -o \
    -name "router_runtime.js" -o \
    -name "tanstack_runner.js" \
  \) -print0 2>/dev/null || true)

  if [[ $found -gt 0 ]]; then
    print_status "$RED" "   -> Found $found payload file(s)."
  else
    print_status "$GREEN" "   -> No known payload files detected."
  fi
}

scan_dependency_markers() {
  local scan_dir=$1
  print_status "$BLUE" "[Stage 3/5] Scanning for malicious dependency markers & scripts..."

  local found=0
  while IFS= read -r -d '' file; do
    [[ "$file" == */node_modules/* ]] && continue

    local content
    content=$(cat "$file" 2>/dev/null || true)
    [[ -z "$content" ]] && continue

    for marker in "${DEPENDENCY_MARKERS[@]}"; do
      if [[ "$content" == *"$marker"* ]]; then
        echo "HIGH|$file|Malicious marker: $marker"
        found=$((found + 1))
      fi
    done
  done < <(find "$scan_dir" -type f \( \
    -name "package.json" -o \
    -name "package-lock.json" -o \
    -name "yarn.lock" -o \
    -name "pnpm-lock.yaml" -o \
    -name "*.js" -o \
    -name "*.ts" -o \
    -name "*.mjs" -o \
    -name "*.cjs" -o \
    -name "*.json" \
  \) -print0 2>/dev/null || true)

  if [[ $found -gt 0 ]]; then
    print_status "$RED" "   -> Found $found malicious marker(s)."
  else
    print_status "$GREEN" "   -> No malicious markers detected."
  fi
}

scan_network_indicators() {
  local scan_dir=$1
  print_status "$BLUE" "[Stage 4/5] Scanning for network/service IOCs in source files..."

  local found=0
  while IFS= read -r -d '' file; do
    [[ "$file" == */node_modules/* ]] && continue

    # Skip binary/non-text files quickly
    if file "$file" 2>/dev/null | grep -qE "(binary|executable|image|archive)"; then
      continue
    fi

    local content
    content=$(cat "$file" 2>/dev/null || true)
    [[ -z "$content" ]] && continue

    for indicator in "${NETWORK_INDICATORS[@]}"; do
      if [[ "$content" == *"$indicator"* ]]; then
        echo "MED|$file|Network IOC: $indicator"
        found=$((found + 1))
      fi
    done

    for marker in "${CAMPAIGN_MARKERS[@]}"; do
      if [[ "$content" == *"$marker"* ]]; then
        echo "CRIT|$file|Campaign marker: $marker"
        found=$((found + 1))
      fi
    done

  done < <(find "$scan_dir" -type f \( \
    -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.cjs" -o \
    -name "*.sh" -o -name "*.py" -o -name "*.ps1" -o -name "*.bat" -o \
    -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "*.toml" \
  \) -print0 2>/dev/null || true)

  if [[ $found -gt 0 ]]; then
    print_status "$YELLOW" "   -> Found $found network/campaign indicator(s)."
  else
    print_status "$GREEN" "   -> No network/campaign indicators detected."
  fi
}

scan_bun_execution() {
  local scan_dir=$1
  print_status "$BLUE" "[Stage 5/5] Scanning for Bun execution & install hooks..."

  local found=0
  while IFS= read -r -d '' file; do
    [[ "$file" == */node_modules/* ]] && continue

    local content
    content=$(cat "$file" 2>/dev/null || true)
    [[ -z "$content" ]] && continue

    # Patterns from attack: prepare script with bun + exit 1, preinstall with bun, etc.
    if grep -qE "(preinstall|prepare|postinstall)[[:space:]]*[:][[:space:]]*.*bun" <<< "$content" 2>/dev/null; then
      echo "MED|$file|Suspicious install hook using Bun"
      found=$((found + 1))
    fi

    if grep -qE "bun run.*tanstack_runner" <<< "$content" 2>/dev/null; then
      echo "HIGH|$file|Bun execution of tanstack_runner detected"
      found=$((found + 1))
    fi

    if grep -qE "exit 1" <<< "$content" 2>/dev/null && grep -qE "(prepare|preinstall|postinstall)" <<< "$content" 2>/dev/null; then
      # This is a broad heuristic: install hook that explicitly exits 1 (fails install after running)
      # Combined with bun it is very suspicious
      if grep -qE "bun" <<< "$content" 2>/dev/null; then
        echo "HIGH|$file|Install hook with 'exit 1' after Bun execution (anti-forensics pattern)"
        found=$((found + 1))
      fi
    fi

  done < <(find "$scan_dir" -type f \( \
    -name "package.json" -o -name "*.yml" -o -name "*.yaml" -o -name "*.sh" \
  \) -print0 2>/dev/null || true)

  if [[ $found -gt 0 ]]; then
    print_status "$YELLOW" "   -> Found $found suspicious Bun execution pattern(s)."
  else
    print_status "$GREEN" "   -> No suspicious Bun execution patterns detected."
  fi
}

# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

generate_report() {
  local tmpfile=$1

  echo
  print_status "$BLUE" "=============================================="
  print_status "$BLUE" "     MINI SHAI-HULUD DETECTION REPORT"
  print_status "$BLUE" "=============================================="
  echo

  local high=0 med=0 crit=0

  # Categorize findings
  while IFS='|' read -r severity file reason; do
    case "$severity" in
      CRIT) crit=$((crit + 1)) ;;
      HIGH) high=$((high + 1)) ;;
      MED)  med=$((med + 1)) ;;
    esac
  done < "$tmpfile"

  if [[ $crit -gt 0 ]]; then
    print_status "$RED" "🚨 CRITICAL FINDINGS ($crit):"
    while IFS='|' read -r severity file reason; do
      [[ "$severity" == "CRIT" ]] && echo -e "   ${RED}• $file${NC}\n     -> $reason"
    done < "$tmpfile"
    echo
  fi

  if [[ $high -gt 0 ]]; then
    print_status "$RED" "🚨 HIGH RISK FINDINGS ($high):"
    while IFS='|' read -r severity file reason; do
      [[ "$severity" == "HIGH" ]] && echo -e "   ${RED}• $file${NC}\n     -> $reason"
    done < "$tmpfile"
    echo
  fi

  if [[ $med -gt 0 ]]; then
    print_status "$YELLOW" "⚠️  MEDIUM RISK FINDINGS ($med):"
    while IFS='|' read -r severity file reason; do
      [[ "$severity" == "MED" ]] && echo -e "   ${YELLOW}• $file${NC}\n     -> $reason"
    done < "$tmpfile"
    echo
  fi

  local total=$((crit + high + med))
  if [[ $total -eq 0 ]]; then
    print_status "$GREEN" "✅ No Mini Shai-Hulud indicators detected."
    print_status "$GREEN" "   Your scanned directory appears clean from this wave."
  else
    print_status "$RED" "SUMMARY: $total total finding(s)"
    print_status "$RED" "   Critical: $crit"
    print_status "$RED" "   High:     $high"
    print_status "$YELLOW" "   Medium:   $med"
    echo
    print_status "$YELLOW" "⚠️  ACTION REQUIRED:"
    print_status "$YELLOW" "   1. If any HIGH/CRIT findings are present, treat the environment as compromised."
    print_status "$YELLOW" "   2. Rotate ALL secrets: npm tokens, GitHub PATs, cloud creds, Vault tokens, K8s SA tokens."
    print_status "$YELLOW" "   3. Review recent npm publishes and GitHub Actions runs for unauthorized activity."
    print_status "$YELLOW" "   4. Check CI logs for Bun execution during 'npm install' or optional dependency failures."
    print_status "$YELLOW" "   5. Delete any suspicious 'shai-hulud' themed git branches or repos."
  fi

  print_status "$BLUE" "=============================================="
  echo
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  local scan_dir="${1:-$HOME/dev}"

  if [[ "$scan_dir" == "--help" || "$scan_dir" == "-h" ]]; then
    usage
  fi

  if [[ ! -d "$scan_dir" ]]; then
    print_status "$RED" "Error: '$scan_dir' is not a directory."
    usage
  fi

  # Resolve absolute path
  scan_dir=$(cd "$scan_dir" && pwd)

  print_status "$GREEN" "Starting Mini Shai-Hulud detection scan..."
  print_status "$BLUE" "Target directory: $scan_dir"
  echo

  load_lookup_tables

  local tmpfile
  tmpfile=$(mktemp /tmp/shai-hulud-detect.XXXXXX)
  trap 'rm -f "$tmpfile"' EXIT

  # Run all scans, appending findings to tmpfile
  scan_package_json "$scan_dir" >> "$tmpfile"
  scan_payload_files "$scan_dir" >> "$tmpfile"
  scan_dependency_markers "$scan_dir" >> "$tmpfile"
  scan_network_indicators "$scan_dir" >> "$tmpfile"
  scan_bun_execution "$scan_dir" >> "$tmpfile"

  generate_report "$tmpfile"

  # Exit code: 1 if any CRIT or HIGH findings
  local exit_code=0
  while IFS='|' read -r severity _; do
    if [[ "$severity" == "CRIT" || "$severity" == "HIGH" ]]; then
      exit_code=1
      break
    fi
  done < "$tmpfile"

  exit $exit_code
}

main "$@"
