$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$RED = "`e[31m"
$GREEN = "`e[32m"
$YELLOW = "`e[33m"
$BLUE = "`e[34m"
$NC = "`e[0m"

$STORAGE_FILE = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
$BACKUP_DIR = "$env:APPDATA\Cursor\User\globalStorage\backups"

function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "$RED[Error]$NC Please run this script as Administrator"
    Write-Host "Right-click the script and select 'Run as Administrator'"
    Read-Host "Press Enter to exit"
    exit 1
}

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

function Get-CursorVersion {
    try {
        $packagePath = "$env:LOCALAPPDATA\Programs\cursor\resources\app\package.json"
        
        if (Test-Path $packagePath) {
            $packageJson = Get-Content $packagePath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Host "$GREEN[Info]$NC Installed Cursor version: v$($packageJson.version)"
                return $packageJson.version
            }
        }
        
        $altPath = "$env:LOCALAPPDATA\cursor\resources\app\package.json"
        if (Test-Path $altPath) {
            $packageJson = Get-Content $altPath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Host "$GREEN[Info]$NC Installed Cursor version: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        Write-Host "$YELLOW[Warning]$NC Unable to detect Cursor version"
        Write-Host "$YELLOW[Hint]$NC Please make sure Cursor is properly installed"
        return $null
    }
    catch {
        
        Write-Host "$RED[Error]$NC Failed to get Cursor version: $_"
        return $null
    }
}

$cursorVersion = Get-CursorVersion
Write-Host ""


Write-Host "$YELLOW[Notice]$NC The latest 0.45.x (supported)"
Write-Host ""


Write-Host "$GREEN[Info]$NC Checking Cursor process..."

function Get-ProcessDetails {
    param($processName)
    // ...existing code...
Write-Host "$BLUE[Debug]$NC Fetching process details for $processName:"
// ...existing code...
    Get-WmiObject Win32_Process -Filter "name='$processName'" | 
        Select-Object ProcessId, ExecutablePath, CommandLine | 
        Format-List
}

$MAX_RETRIES = 5
$WAIT_TIME = 1

function Close-CursorProcess {
    param($processName)
    
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
   if ($process) {
    Write-Host "$YELLOW[Warning]$NC Found $processName is running"
    Get-ProcessDetails $processName

    Write-Host "$YELLOW[Warning]$NC Attempting to close $processName..."
    Stop-Process -Name $processName -Force

    $retryCount = 0
    while ($retryCount -lt $MAX_RETRIES) {
        $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if (-not $process) { break }

        $retryCount++
        if ($retryCount -ge $MAX_RETRIES) {
            Write-Host "$RED[Error]$NC Unable to close $processName after $MAX_RETRIES attempts"
            Get-ProcessDetails $processName
            Write-Host "$RED[Error]$NC Please close the process manually and try again"
            Read-Host "Press Enter to exit"
            exit 1
        }
        Write-Host "$YELLOW[Warning]$NC Waiting for process to close, attempt $retryCount/$MAX_RETRIES..."
        Start-Sleep -Seconds $WAIT_TIME
    }
    Write-Host "$GREEN[Info]$NC $processName closed successfully"
}



}

// Close all Cursor processes
Close-CursorProcess "Cursor"
Close-CursorProcess "cursor"

// Create backup directory
if (-not (Test-Path $BACKUP_DIR)) {
    New-Item -ItemType Directory -Path $BACKUP_DIR | Out-Null
}

// Backup existing config
if (Test-Path $STORAGE_FILE) {
    Write-Host "$GREEN[Info]$NC Backing up config file..."
    $backupName = "storage.json.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item $STORAGE_FILE "$BACKUP_DIR\$backupName"
}

// Generate new ID
Write-Host "$GREEN[Info]$NC Generating new ID..."

// Add this function after color definitions
function Get-RandomHex {
    param (
        [int]$length
    )
    
    $bytes = New-Object byte[] ($length)
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $rng.GetBytes($bytes)
    $hexString = [System.BitConverter]::ToString($bytes) -replace '-',''
    $rng.Dispose()
    return $hexString
}
function New-StandardMachineId {
    $template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    $result = $template -replace '[xy]', {
        param($match)
        $r = [Random]::new().Next(16)
        $v = if ($match.Value -eq "x") { $r } else { ($r -band 0x3) -bor 0x8 }
        return $v.ToString("x")
    }
    return $result
}
# Generate new IDs
$MAC_MACHINE_ID = New-StandardMachineId
$UUID = [System.Guid]::NewGuid().ToString()

# Convert "auth0|user_" string into bytes and then to hexadecimal
$prefixBytes = [System.Text.Encoding]::UTF8.GetBytes("auth0|user_")
$prefixHex = -join ($prefixBytes | ForEach-Object { '{0:x2}' -f $_ })

# Generate a 32-byte (64 hex characters) random part for machineId
$randomPart = Get-RandomHex -length 32
$MACHINE_ID = "$prefixHex$randomPart"

# Generate SQM ID in uppercase GUID format
$SQM_ID = "{$([System.Guid]::NewGuid().ToString().ToUpper())}"

# Check for Administrator privileges before updating MachineGuid
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "$RED[Error]$NC Please run this script as Administrator"
    Start-Process powershell "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Update-MachineGuid {
    try {
        # Check if registry path exists
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        if (-not (Test-Path $registryPath)) {
            throw "Registry path does not exist: $registryPath"
        }

        # Get current MachineGuid
        $currentGuid = Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop
        if (-not $currentGuid) {
            throw "Unable to retrieve current MachineGuid"
        }

        $originalGuid = $currentGuid.MachineGuid
        Write-Host "$GREEN[Info]$NC Current registry value:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
        Write-Host "    MachineGuid    REG_SZ    $originalGuid"

        # Create backup directory if it doesn’t exist
        if (-not (Test-Path $BACKUP_DIR)) {
            New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
        }

        # Create backup file
        $backupFile = "$BACKUP_DIR\MachineGuid_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
        $backupResult = Start-Process "reg.exe" -ArgumentList "export", "`"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`"", "`"$backupFile`"" -NoNewWindow -Wait -PassThru

        if ($backupResult.ExitCode -eq 0) {
            Write-Host "$GREEN[Info]$NC Registry key backed up to: $backupFile"
        } else {
            Write-Host "$YELLOW[Warning]$NC Backup creation failed, continuing execution..."
        }

        # Generate new GUID
        $newGuid = [System.Guid]::NewGuid().ToString()

        # Update registry
        Set-ItemProperty -Path $registryPath -Name MachineGuid -Value $newGuid -Force -ErrorAction Stop

        # Verify update
        $verifyGuid = (Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop).MachineGuid
        if ($verifyGuid -ne $newGuid) {
            throw "Registry verification failed: updated value ($verifyGuid) does not match expected ($newGuid)"
        }

        Write-Host "$GREEN[Info]$NC Registry updated successfully:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
        Write-Host "    MachineGuid    REG_SZ    $newGuid"
        return $true
    }
    catch {
        Write-Host "$RED[Error]$NC Registry operation failed: $($_.Exception.Message)"

        # Attempt to restore from backup
        if ($backupFile -and (Test-Path $backupFile)) {
            Write-Host "$YELLOW[Restore]$NC Attempting to restore from backup..."
            $restoreResult = Start-Process "reg.exe" -ArgumentList "import", "`"$backupFile`"" -NoNewWindow -Wait -PassThru

            if ($restoreResult.ExitCode -eq 0) {
                Write-Host "$GREEN[Restore successful]$NC Original registry value restored"
            } else {
                Write-Host "$RED[Error]$NC Restore failed. Please manually import backup file: $backupFile"
            }
        } else {
            Write-Host "$YELLOW[Warning]$NC Backup file not found or backup failed, automatic restoration not possible"
        }
        return $false
    }
}

# Create or update configuration file
Write-Host "$GREEN[Info]$NC Updating configuration..."

try {
    # Check if the configuration file exists
    if (-not (Test-Path $STORAGE_FILE)) {
        Write-Host "$RED[Error]$NC Configuration file not found: $STORAGE_FILE"
        Write-Host "$YELLOW[Tip]$NC Please install and run Cursor at least once before using this script"
        Read-Host "Press Enter to exit"
        exit 1
    }

    # Read existing configuration file
    try {
        $originalContent = Get-Content $STORAGE_FILE -Raw -Encoding UTF8
        
        # Convert JSON string into PowerShell object
        $config = $originalContent | ConvertFrom-Json 

        # Backup existing values
        $oldValues = @{
            'machineId'    = $config.'telemetry.machineId'
            'macMachineId' = $config.'telemetry.macMachineId'
            'devDeviceId'  = $config.'telemetry.devDeviceId'
            'sqmId'        = $config.'telemetry.sqmId'
        }

        # Update specific fields
        $config.'telemetry.machineId'    = $MACHINE_ID
        $config.'telemetry.macMachineId' = $MAC_MACHINE_ID
        $config.'telemetry.devDeviceId'  = $UUID
        $config.'telemetry.sqmId'        = $SQM_ID

        # Convert updated object back to JSON and save
        $updatedJson = $config | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText(
            [System.IO.Path]::GetFullPath($STORAGE_FILE), 
            $updatedJson, 
            [System.Text.Encoding]::UTF8
        )
        Write-Host "$GREEN[Info]$NC Configuration file updated successfully"
    } catch {
        # On error, restore original content
        if ($originalContent) {
            [System.IO.File]::WriteAllText(
                [System.IO.Path]::GetFullPath($STORAGE_FILE), 
                $originalContent, 
                [System.Text.Encoding]::UTF8
            )
        }
        throw "Failed to process JSON: $_"
    }

    # Automatically update MachineGuid without asking
    Update-MachineGuid

    # Show updated results
    Write-Host ""
    Write-Host "$GREEN[Info]$NC Updated configuration:"
    Write-Host "$BLUE[Debug]$NC machineId: $MACHINE_ID"
    Write-Host "$BLUE[Debug]$NC macMachineId: $MAC_MACHINE_ID"
    Write-Host "$BLUE[Debug]$NC devDeviceId: $UUID"
    Write-Host "$BLUE[Debug]$NC sqmId: $SQM_ID"

    # Show directory structure
    Write-Host ""
    Write-Host "$GREEN[Info]$NC File structure:"
    Write-Host "$BLUE$env:APPDATA\Cursor\User$NC"
    Write-Host "├── globalStorage"
    Write-Host "│   ├── storage.json (modified)"
    Write-Host "│   └── backups"

    # List backup files
    $backupFiles = Get-ChildItem "$BACKUP_DIR\*" -ErrorAction SilentlyContinue
    if ($backupFiles) {
        foreach ($file in $backupFiles) {
            Write-Host "│       └── $($file.Name)"
        }
    } else {
        Write-Host "│       └── (empty)"
    }

    # Show information
    Write-Host ""
    Write-Host "$GREEN================================$NC"
    Write-Host ""
    Write-Host "$GREEN[Info]$NC Please restart Cursor to apply the new configuration"
    Write-Host ""

    # Ask user whether to disable automatic updates
    Write-Host ""
    Write-Host "$YELLOW[Prompt]$NC Do you want to disable Cursor auto-update feature?"
    Write-Host "0) No - Keep default (just press Enter)"
    Write-Host "1) Yes - Disable auto-update"
    $choice = Read-Host "Enter your choice (0)"

    if ($choice -eq "1") {
        Write-Host ""
        Write-Host "$GREEN[Info]$NC Processing auto-update disabling..."
        $updaterPath = "$env:LOCALAPPDATA\cursor-updater"

        function Show-ManualGuide {
            Write-Host ""
            Write-Host "$YELLOW[Warning]$NC Auto-disable failed. Please try manual steps:"
            Write-Host "1. Open PowerShell as Administrator"
            Write-Host "2. Paste the following commands:"
            Write-Host "$BLUE Command1 - Delete existing directory (if any):$NC"
            Write-Host "Remove-Item -Path `"$updaterPath`" -Force -Recurse -ErrorAction SilentlyContinue"
            Write-Host ""
            Write-Host "$BLUE Command2 - Create blocking file:$NC"
            Write-Host "New-Item -Path `"$updaterPath`" -ItemType File -Force | Out-Null"
            Write-Host ""
            Write-Host "$BLUE Command3 - Set read-only attribute:$NC"
            Write-Host "Set-ItemProperty -Path `"$updaterPath`" -Name IsReadOnly -Value `$true"
            Write-Host ""
            Write-Host "$BLUE Command4 - Set permissions (optional):$NC"
            Write-Host "icacls `"$updaterPath`" /inheritance:r /grant:r `"$($env:USERNAME):(R)`""
            Write-Host ""
            Write-Host "$YELLOW How to verify:$NC"
            Write-Host "1. Run: Get-ItemProperty `"$updaterPath`""
            Write-Host "2. Confirm IsReadOnly is True"
            Write-Host "3. Run: icacls `"$updaterPath`""
            Write-Host "4. Confirm only read permission"
            Write-Host ""
            Write-Host "$YELLOW[Tip]$NC Restart Cursor after completing steps"
        }

        try {
            # Check if cursor-updater path exists
            if (Test-Path $updaterPath) {
                if ((Get-Item $updaterPath) -is [System.IO.FileInfo]) {
                    Write-Host "$GREEN[Info]$NC Auto-update already blocked; nothing to do"
                    return
                } else {
                    try {
                        Remove-Item -Path $updaterPath -Force -Recurse -ErrorAction Stop
                        Write-Host "$GREEN[Info]$NC cursor-updater directory deleted"
                    }
                    catch {
                        Write-Host "$RED[Error]$NC Failed to delete cursor-updater directory"
                        Show-ManualGuide
                        return
                    }
                }
            }

            # Create block file
            try {
                New-Item -Path $updaterPath -ItemType File -Force -ErrorAction Stop | Out-Null
                Write-Host "$GREEN[Info]$NC Block file created successfully"
            }
            catch {
                Write-Host "$RED[Error]$NC Failed to create block file"
                Show-ManualGuide
                return
            }

            # Set file permissions
            try {
                Set-ItemProperty -Path $updaterPath -Name IsReadOnly -Value $true -ErrorAction Stop
                
                $result = Start-Process "icacls.exe" -ArgumentList "`"$updaterPath`" /inheritance:r /grant:r `"$($env:USERNAME):(R)`"" -Wait -NoNewWindow -PassThru
                if ($result.ExitCode -ne 0) {
                    throw "icacls command failed"
                }
                
                Write-Host "$GREEN[Info]$NC File permission set successfully"
            }
            catch {
                Write-Host "$RED[Error]$NC Failed to set file permission"
                Show-ManualGuide
                return
            }

            # Verify permissions
            try {
                $fileInfo = Get-ItemProperty $updaterPath
                if (-not $fileInfo.IsReadOnly) {
                    Write-Host "$RED[Error]$NC Verification failed: file may not be read-only"
                    Show-ManualGuide
                    return
                }
            }
            catch {
                Write-Host "$RED[Error]$NC Permission verification failed"
                Show-ManualGuide
                return
            }

            Write-Host "$GREEN[Info]$NC Auto-update disabled successfully"
        }
        catch {
            Write-Host "$RED[Error]$NC Unknown error occurred: $_"
            Show-ManualGuide
        }
    }
    else {
        Write-Host "$GREEN[Info]$NC Keeping default settings, no changes made"
    }

    # Keep valid registry update
    Update-MachineGuid

} catch {
    Write-Host "$RED[Error]$NC Main operation failed: $_"
    Write-Host "$YELLOW[Attempt]$NC Trying fallback method..."

    try {
        # Fallback: Use Add-Content
        $tempFile = [System.IO.Path]::GetTempFileName()
        $config | ConvertTo-Json | Set-Content -Path $tempFile -Encoding UTF8
        Copy-Item -Path $tempFile -Destination $STORAGE_FILE -Force
        Remove-Item -Path $tempFile
        Write-Host "$GREEN[Info]$NC Fallback method wrote configuration successfully"
    } catch {
        Write-Host "$RED[Error]$NC All attempts failed"
        Write-Host "Error details: $_"
        Write-Host "Target file: $STORAGE_FILE"
        Write-Host "Please ensure sufficient file access permissions"
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host ""
Read-Host "Press Enter to exit"
exit 0
function Write-ConfigFile {
    param($config, $filePath)
    
    try {
        # Use UTF8 encoding without BOM
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        $jsonContent = $config | ConvertTo-Json -Depth 10
        
        # Normalize line endings to LF
        $jsonContent = $jsonContent.Replace("`r`n", "`n")
        
        [System.IO.File]::WriteAllText(
            [System.IO.Path]::GetFullPath($filePath),
            $jsonContent,
            $utf8NoBom
        )
        
        Write-Host "$GREEN[Info]$NC Configuration file written successfully (UTF8 without BOM)"
    }
    catch {
        throw "Failed to write configuration file: $_"
    }
}

function Compare-Version {
    param (
        [string]$version1,
        [string]$version2
    )
    
    try {
        # Extract numeric parts and compare as Version objects
        $v1 = [version]($version1 -replace '[^\d\.].*$')
        $v2 = [version]($version2 -replace '[^\d\.].*$')
        return $v1.CompareTo($v2)
    }
    catch {
        Write-Host "$RED[Error]$NC Version comparison failed: $_"
        return 0
    }
}

# Add version check at the start of main flow
Write-Host "$GREEN[Info]$NC Checking Cursor version..."
$cursorVersion = Get-CursorVersion

if ($cursorVersion) {
    $compareResult = Compare-Version $cursorVersion "0.45.0"
    
    if ($compareResult -ge 0) {
        Write-Host "$RED[Error]$NC Current version ($cursorVersion) is not supported"
        Write-Host "$YELLOW[Suggestion]$NC Please use version v0.44.11 or earlier"
        Write-Host "$YELLOW[Suggestion]$NC You can download supported versions here:"
        Write-Host "Windows: https://download.todesktop.com/230313mzl4w4u92/Cursor%20Setup%200.44.11%20-%20Build%20250103fqxdt5u9z-x64.exe"
        Write-Host "Mac ARM64: https://dl.todesktop.com/230313mzl4w4u92/versions/0.44.11/mac/zip/arm64"
        Read-Host "Press Enter to exit"
        exit 1
    }
    else {
        Write-Host "$GREEN[Info]$NC Current version ($cursorVersion) supports reset functionality"
    }
}
else {
    Write-Host "$YELLOW[Warning]$NC Could not detect version, proceeding anyway..."
}
