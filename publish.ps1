# Run from the unzipped project folder in Windows PowerShell 7+.
# Requires Git, Python, and authenticated GitHub access (Git Credential Manager or gh auth login).
# Makes a feature branch and opens no pull request automatically; production site stays unchanged.
param(
    [string]$RepoUrl = 'https://github.com/Abtsega123/Abtsega123.github.io.git',
    [string]$BranchName = 'security-portfolio-refresh-2026'
)
$ErrorActionPreference = 'Stop'
$destination = Join-Path (Split-Path -Parent $PSScriptRoot) 'eca-portfolio-publish'
if (Test-Path $destination) { throw "Destination already exists: $destination. Choose an empty folder and rerun." }
& git clone $RepoUrl $destination
if ($LASTEXITCODE -ne 0) { throw 'Clone failed. Confirm access to the repository.' }
Push-Location $destination
try {
    & git switch -c $BranchName
    if ($LASTEXITCODE -ne 0) { throw 'Could not create a feature branch.' }
    foreach ($item in @('index.html','styles.css','app.js','assets','projects','tests','.github','.gitignore','README.md','SECURITY.md','publish.ps1')) {
        $src = Join-Path $PSScriptRoot $item
        $dst = Join-Path $destination $item
        if ((Test-Path -LiteralPath $src -PathType Container) -and (Test-Path -LiteralPath $dst -PathType Container)) {
            Get-ChildItem -LiteralPath $src -Force | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $dst -Recurse -Force }
        } else {
            Copy-Item -LiteralPath $src -Destination $dst -Recurse -Force
        }
    }
    & python -m pip install -r projects/secure-ticket-api/requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed.' }
    & python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Project tests failed. Nothing was pushed.' }
    & python tests/site_smoke.py
    if ($LASTEXITCODE -ne 0) { throw 'Site checks failed. Nothing was pushed.' }
    & git add index.html styles.css app.js assets projects tests .github .gitignore README.md SECURITY.md publish.ps1
    & git commit -m 'Build evidence-based security engineering portfolio and working labs'
    if ($LASTEXITCODE -ne 0) { throw 'Commit failed.' }
    & git push -u origin $BranchName
    if ($LASTEXITCODE -ne 0) { throw 'Push failed. Check GitHub authentication and repository permissions.' }
    Write-Host 'Feature branch pushed. Review and merge the pull request on GitHub before updating the live site.' -ForegroundColor Green
} finally { Pop-Location }
