#!/usr/bin/env bash
# install-test-jdks.sh
#
# Installs all JDK versions needed to run the full multi-JDK test matrix locally via SDKMAN,
# then generates ~/.m2/toolchains.xml from the discovered JDKs.
#
# Usage:
#   ./install-test-jdks.sh
#
# After running this script, activate each profile you want to test against, e.g.:
#   ./mvnw verify -P jdk-8,jdk-11,jdk-21,jdk-25
#
# The build JDK must be JDK 17+. If you are not already on JDK 17:
#   sdk use java <17.x.x-tem>

set -euo pipefail

# ============================================================
# JDK versions to install.
# Update these when new patch releases are available.
# Find current versions with: sdk list java
#
# NOTE: Temurin does not provide JDK 8 on all platforms (e.g.
# macOS/ARM). Zulu is used for JDK 8 as a reliable fallback.
# ============================================================
JDKS=(
  "8.0.492-zulu"   # JDK 8  - minimum supported runtime
  "11.0.31-tem"    # JDK 11
  "17.0.19-tem"    # JDK 17 - required build JDK
  "21.0.11-tem"    # JDK 21
  "25.0.3-tem"     # JDK 25
)
# ============================================================

if ! command -v sdk &>/dev/null; then
  echo "ERROR: SDKMAN not found. Install it from https://sdkman.io" >&2
  exit 1
fi

# Source SDKMAN so 'sdk' commands work in this script
# shellcheck disable=SC1090
source "${SDKMAN_DIR:-$HOME/.sdkman}/bin/sdkman-init.sh"

echo "Installing test JDKs via SDKMAN..."
echo "(Already-installed versions will be skipped)"
echo

for jdk in "${JDKS[@]}"; do
  sdk install java "$jdk" || true
done

echo
echo "Done. Generating ~/.m2/toolchains.xml from discovered JDKs..."
./mvnw --no-transfer-progress -q \
  org.apache.maven.plugins:maven-toolchains-plugin:3.2.0:generate-jdk-toolchains-xml \
  -Dtoolchain.file="${HOME}/.m2/toolchains.xml"

echo
echo "To run the full multi-JDK test matrix:"
echo "  ./mvnw verify -P jdk-8,jdk-11,jdk-17,jdk-21,jdk-25"
echo
echo "To run a single JDK profile (e.g., JDK 8 only):"
echo "  ./mvnw verify -P jdk-8"
