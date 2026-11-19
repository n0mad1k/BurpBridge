#!/usr/bin/env bash
# Build BurpBridge.jar using Burp's bundled JDK and Montoya API (in burpsuite.jar).
# Override BURP if your Burp install lives elsewhere.
set -euo pipefail
BURP="${BURP:-$HOME/AppData/Local/Programs/BurpSuite}"
JAVAC="$BURP/jre/bin/javac.exe"
JAR="$BURP/burpsuite.jar"
here="$(cd "$(dirname "$0")" && pwd)"
rm -rf "$here/out"; mkdir -p "$here/out"
"$JAVAC" -implicit:none -cp "$JAR" -d "$here/out" "$here/src/BurpBridge.java"
( cd "$here/out" && py -3 -c "import zipfile; z=zipfile.ZipFile('../BurpBridge.jar','w',zipfile.ZIP_DEFLATED); z.write('BurpBridge.class'); z.close()" )
echo "built: $here/BurpBridge.jar"
