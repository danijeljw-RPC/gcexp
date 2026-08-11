[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = $PSScriptRoot
$solution = Join-Path $repositoryRoot 'gcexp.slnx'
$project = Join-Path $repositoryRoot 'src/gcexp.csproj'
$publishDirectory = Join-Path $repositoryRoot 'publish/win-x64'

$expectedPublishDirectory = [System.IO.Path]::GetFullPath(
    (Join-Path $repositoryRoot 'publish/win-x64'))
$resolvedPublishDirectory = [System.IO.Path]::GetFullPath($publishDirectory)

if (-not $resolvedPublishDirectory.Equals(
    $expectedPublishDirectory,
    [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean unexpected publish directory: $resolvedPublishDirectory"
}

if (Test-Path -LiteralPath $resolvedPublishDirectory) {
    Remove-Item -LiteralPath $resolvedPublishDirectory -Recurse -Force
}

Push-Location $repositoryRoot
try {
    dotnet restore $solution --locked-mode
    if ($LASTEXITCODE -ne 0) { throw 'dotnet restore failed.' }

    dotnet restore $project --runtime win-x64 --locked-mode
    if ($LASTEXITCODE -ne 0) { throw 'dotnet runtime restore failed.' }

    $auditJson = dotnet list $solution package --vulnerable --include-transitive --no-restore --format json
    if ($LASTEXITCODE -ne 0) { throw 'NuGet vulnerability audit failed.' }

    $audit = $auditJson | ConvertFrom-Json
    $vulnerablePackages = @(
        foreach ($auditProject in $audit.projects) {
            foreach ($framework in @($auditProject.frameworks)) {
                foreach ($package in @($framework.topLevelPackages) + @($framework.transitivePackages)) {
                    if ($null -ne $package -and
                        $null -ne $package.vulnerabilities -and
                        @($package.vulnerabilities).Count -gt 0) {
                        "$($package.id) $($package.resolvedVersion)"
                    }
                }
            }
        }
    )
    if ($vulnerablePackages.Count -gt 0) {
        throw "Vulnerable NuGet packages detected: $($vulnerablePackages -join ', ')"
    }
    Write-Host 'NuGet vulnerability audit passed.'

    dotnet test $solution --configuration Release --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'dotnet test failed.' }

    dotnet format $solution --verify-no-changes --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'dotnet format verification failed.' }

    dotnet build $solution --configuration Release --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed.' }

    dotnet publish $project `
        --configuration Release `
        --runtime win-x64 `
        --self-contained true `
        --no-restore `
        --output $resolvedPublishDirectory `
        -p:StripSymbols=true `
        -p:DebugSymbols=false `
        -p:DebugType=None
    if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed.' }

    $nativeSymbols = Join-Path $resolvedPublishDirectory 'gcexp.pdb'
    if (Test-Path -LiteralPath $nativeSymbols -PathType Leaf) {
        Remove-Item -LiteralPath $nativeSymbols -Force
    }

    Write-Host "Published win-x64 distribution: $resolvedPublishDirectory"
}
finally {
    Pop-Location
}
