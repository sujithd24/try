$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$RED = "`e[31m"
$GREEN = "`e[32m"
$YELLOW = "`e[33m"
$BLUE = "`e[34m"
$NC = "`e[0m"

Clear-Host
Write-Host @"

    ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ 
   ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔══██╗
   ██║     ██║   ██║██████╔╝███████╗██║   ██║██████╔╝
   ██║     ██║   ██║██╔══██╗╚════██║██║   ██║██╔══██╗
   ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝██║  ██║
    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝

"@
Write-Host "$BLUE================================$NC"
Write-Host "BY SUJITH copyright 2025"

$STORAGE_FILE = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
$BACKUP_DIR = "$env:APPDATA\Cursor\User\globalStorage\backups"

$MAC_MACHINE_ID = New-StandardMachineId
$UUID = [System.Guid]::NewGuid().ToString()

$prefixBytes = [System.Text.Encoding]::UTF8.GetBytes("auth0|user_")
$prefixHex = -join ($prefixBytes | ForEach-Object { '{0:x2}' -f $_ })

$randomPart = Get-RandomHex -length 32
$MACHINE_ID = "$prefixHex$randomPart"

$SQM_ID = "{$([System.Guid]::NewGuid().ToString().ToUpper())}"

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "$RED[Error]$NC Please run this script as Administrator"
    Start-Process powershell "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Update-MachineGuid {
    try {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography"

        if (-not (Test-Path $registryPath)) {
            throw "Registry path does not exist: $registryPath"
        }

        $currentGuid = Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop
        $originalGuid = $currentGuid.MachineGuid

        Write-Host "$GREEN[Info]$NC Current registry value:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
        Write-Host "    MachineGuid    REG_SZ    $originalGuid"

        if (-not (Test-Path $BACKUP_DIR)) {
            New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
        }

        $backupFile = "$BACKUP_DIR\MachineGuid_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
        $backupResult = Start-Process "reg.exe" -ArgumentList "export", "`"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`"", "`"$backupFile`"" -NoNewWindow -Wait -PassThru
        
        if ($backupResult.ExitCode -eq 0) {
            Write-Host "$GREEN[Info]$NC Backup created: $backupFile"
        } else {
            Write-Host "$YELLOW[Warning]$NC Backup failed, continuing..."
        }

        $newGuid = [System.Guid]::NewGuid().ToString()

        Set-ItemProperty -Path $registryPath -Name MachineGuid -Value $newGuid -Force -ErrorAction Stop

        $verifyGuid = (Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop).MachineGuid
        if ($verifyGuid -ne $newGuid) {
            throw "Registry verification failed: expected ($newGuid), got ($verifyGuid)"
        }

        Write-Host "$GREEN[Info]$NC Registry updated successfully:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
        Write-Host "    MachineGuid    REG_SZ    $newGuid"
        return $true
    } catch {
        Write-Host "$RED[Error]$NC Registry operation failed: $($_.Exception.Message)"

        if ($backupFile -and (Test-Path $backupFile)) {
            Write-Host "$YELLOW[Restore]$NC Attempting backup restoration..."
            $restoreResult = Start-Process "reg.exe" -ArgumentList "import", "`"$backupFile`"" -NoNewWindow -Wait -PassThru
            
            if ($restoreResult.ExitCode -eq 0) {
                Write-Host "$GREEN[Restore successful]$NC Registry restored from backup"
            } else {
                Write-Host "$RED[Error]$NC Restoration failed. Please manually import backup: $backupFile"
            }
        } else {
            Write-Host "$YELLOW[Warning]$NC Backup file not found or creation failed, cannot restore automatically"
        }

        return $false
    }
}

Write-Host "$GREEN[Info]$NC Updating configuration..."

if (-not (Test-Path $STORAGE_FILE)) {
    Write-Host "$RED[Error]$NC Configuration file not found: $STORAGE_FILE"
    Write-Host "$YELLOW[Hint]$NC Please run Cursor once before using this script"
    Read-Host "Press Enter to exit"
    exit 1
}

$originalContent = Get-Content $STORAGE_FILE -Raw -Encoding UTF8
$config = $originalContent | ConvertFrom-Json

$oldValues = @{
    'machineId' = $config.'telemetry.machineId'
    'macMachineId' = $config.'telemetry.macMachineId'
    'devDeviceId' = $config.'telemetry.devDeviceId'
    'sqmId' = $config.'telemetry.sqmId'
}

$config.'telemetry.machineId' = $MACHINE_ID
$config.'telemetry.macMachineId' = $MAC_MACHINE_ID
$config.'telemetry.devDeviceId' = $UUID
$config.'telemetry.sqmId' = $SQM_ID

$updatedJson = $config | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($STORAGE_FILE), $updatedJson, [System.Text.Encoding]::UTF8)

Write-Host "$GREEN[Info]$NC Successfully updated configuration file"

Update-MachineGuid

Write-Host "$GREEN[Info]$NC Configuration has been updated:"
Write-Host "machineId: $MACHINE_ID"
Write-Host "macMachineId: $MAC_MACHINE_ID"
Write-Host "devDeviceId: $UUID"
Write-Host "sqmId: $SQM_ID"

Write-Host "Directory structure:"
Write-Host "$env:APPDATA\Cursor\User"
Write-Host "├── globalStorage"
Write-Host "│   ├── storage.json (modified)"
Write-Host "│   └── backups"

$backupFiles = Get-ChildItem "$BACKUP_DIR\*" -ErrorAction SilentlyContinue
foreach ($file in $backupFiles) {
    Write-Host "│       └── $($file.Name)"
}

$choice = 1

if ($choice -eq "1") {
    $updaterPath = "$env:LOCALAPPDATA\cursor-updater"
    
    if (Test-Path $updaterPath) {
        if ((Get-Item $updaterPath) -is [System.IO.FileInfo]) {
            Write-Host "$GREEN[Info]$NC Update blocker already exists"
            return
        } else {
            Remove-Item -Path $updaterPath -Force -Recurse
        }
    }

    New-Item -Path $updaterPath -ItemType File -Force
    Set-ItemProperty -Path $updaterPath -Name IsReadOnly -Value $true
    Start-Process "icacls.exe" -ArgumentList "`"$updaterPath`" /inheritance:r /grant:r `"$env:USERNAME:(R)`"" -Wait -NoNewWindow -PassThru

    Write-Host "$GREEN[Info]$NC Auto-update disabled successfully"
} else {
    Write-Host "$GREEN[Info]$NC Auto-update remains unchanged"
}

Update-MachineGuid

Read-Host "Press Enter to exit"
exit 0

function Write-ConfigFile {
    param($config, $filePath)

    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        $jsonContent = $config | ConvertTo-Json -Depth 10
        $jsonContent = $jsonContent.Replace("`r`n", "`n")

        [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($filePath), $jsonContent, $utf8NoBom)

        Write-Host "$GREEN[Info]$NC Configuration file written successfully (UTF8 without BOM)"
    } catch {
        throw "Failed to write config file: $_"
    }
}

function Compare-Version {
    param (
        [string]$version1,
        [string]$version2
    )

    try {
        $v1 = [version]($version1 -replace '[^\d\.].*$')
        $v2 = [version]($version2 -replace '[^\d\.].*$')
        return $v1.CompareTo($v2)
    } catch {
        Write-Host "$RED[Error]$NC Version comparison failed: $_"
        return 0
    }
}

Write-Host "$GREEN[Info]$NC Checking Cursor version..."
$cursorVersion = Get-CursorVersion

if ($cursorVersion) {
    $compareResult = Compare-Version $cursorVersion "0.45.0"
    if ($compareResult -ge 0) {
        Write-Host "$RED[Error]$NC Current version ($cursorVersion) not supported"
        Write-Host "$YELLOW[Hint]$NC Please use version v0.44.11 or earlier"
        Write-Host "Windows: https://download.todesktop.com/230313mzl4w4u92/Cursor%20Setup%200.44.11%20-%20Build%20250103fqxdt5u9z-x64.exe"
        Write-Host "Mac ARM64: https://dl.todesktop.com/230313mzl4w4u92/versions/0.44.11/mac/zip/arm64"
        Read-Host "Press Enter to exit"
        exit 1
    } else {
        Write-Host "$GREEN[Info]$NC Current version ($cursorVersion) supports reset functionality"
    }
} else {
    Write-Host "$YELLOW[Warning]$NC Unable to detect version, proceeding anyway..."
}
