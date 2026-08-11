#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
solution="$repository_root/gcexp.slnx"
project="$repository_root/src/gcexp.csproj"
publish_directory="$repository_root/publish/linux-x64"
expected_publish_directory="$repository_root/publish/linux-x64"

if [[ "$publish_directory" != "$expected_publish_directory" ]]; then
    printf 'Refusing to clean unexpected publish directory: %s\n' "$publish_directory" >&2
    exit 1
fi

if [[ -e "$publish_directory" ]]; then
    rm -rf -- "$publish_directory"
fi

cd -- "$repository_root"

dotnet restore "$solution" --locked-mode
dotnet restore "$project" --runtime linux-x64 --locked-mode

audit_json="$(dotnet list "$solution" package --vulnerable --include-transitive --no-restore --format json)"
python3 -c '
import json
import sys

audit = json.load(sys.stdin)
vulnerable = []
for project in audit.get("projects", []):
    for framework in project.get("frameworks", []):
        packages = framework.get("topLevelPackages", []) + framework.get("transitivePackages", [])
        for package in packages:
            if package.get("vulnerabilities"):
                vulnerable.append(f"{package.get('"'"'id'"'"')} {package.get('"'"'resolvedVersion'"'"')}")

if vulnerable:
    print("Vulnerable NuGet packages detected: " + ", ".join(vulnerable), file=sys.stderr)
    raise SystemExit(1)
' <<< "$audit_json"
printf 'NuGet vulnerability audit passed.\n'

dotnet test "$solution" --configuration Release --no-restore
dotnet format "$solution" --verify-no-changes --no-restore
dotnet build "$solution" --configuration Release --no-restore

dotnet publish "$project" \
    --configuration Release \
    --runtime linux-x64 \
    --self-contained true \
    --no-restore \
    --output "$publish_directory" \
    -p:StripSymbols=true \
    -p:DebugSymbols=false \
    -p:DebugType=None

native_symbols="$publish_directory/gcexp.dbg"
if [[ -f "$native_symbols" ]]; then
    rm -f -- "$native_symbols"
fi

printf 'Published linux-x64 distribution: %s\n' "$publish_directory"
