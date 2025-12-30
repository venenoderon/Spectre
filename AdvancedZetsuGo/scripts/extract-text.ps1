param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [string]$Output = "payload.bin",
    [string]$Section = ".text"
)

if (-not (Test-Path $Binary)) {
    Write-Error "Binary not found: $Binary"
    exit 1
}

$objcopy = Get-Command "llvm-objcopy" -ErrorAction SilentlyContinue
if (-not $objcopy) {
    $objcopy = Get-Command "objcopy" -ErrorAction SilentlyContinue
}

if (-not $objcopy) {
    Write-Warning "No objcopy found. Add VS Llvm\\bin or MinGW to PATH."
    exit 2
}

& $objcopy.Source --dump-section "$Section=$Output" $Binary
if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Extracted $Section from $Binary -> $Output"
} else {
    Write-Error "objcopy failed with $LASTEXITCODE"
    exit $LASTEXITCODE
}

