#Requires -RunAsAdministrator

<#
.SYNOPSIS

Strong Mapping Check and Delete if not there
******IMPORTANT Change Line 156 to your Certificate Authority**********

    Removes certificates from all user stores that contain "YOUR CERT ISSUER ON (Change to yours on Line 156)" in issuer but does not contain "microsoft.com" in Subject Alternative Name i.e doesnt contain the tag:url for strong mapping

.DESCRIPTION
    This script must be run as SYSTEM to access all user profiles and their certificate stores.
    It searches through each user's personal certificate store and removes certificates that
    have an issuer containing "Fignon" AND don't have "microsoft.com" in their Subject Alternative Name (SAN).
.NOTES
    - Must be run as SYSTEM account
    - Creates a log file in C:\Windows\Temp\
    - Use with caution as this permanently deletes certificates
#>

# Set up logging
$LogFile = "C:\Windows\Temp\CertificateCleanup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$TimeStamp] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
}

function Test-MicrosoftSAN {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    
    try {
        # Get Subject Alternative Name extension
        $sanExtension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
        
        if ($sanExtension) {
            $sanString = $sanExtension.Format($false)
            Write-Log "  SAN Content: $sanString"
            
            # Check if SAN contains microsoft.com
            if ($sanString -like "*microsoft.com*") {
                return $true
            }
        } else {
            Write-Log "  No SAN extension found"
        }
        
        return $false
    }
    catch {
        Write-Log "  Error reading SAN: $($_.Exception.Message)"
        return $false
    }
}

# Start main execution
Write-Log "Starting certificate cleanup process"
Write-Log "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

# Verify running as SYSTEM
$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($currentIdentity.Name -ne "NT AUTHORITY\SYSTEM") {
    Write-Log "ERROR: This script must be run as SYSTEM account"
    exit 1
}

# Get all user profiles
$UserProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { 
    $_.Special -eq $false -and 
    $_.LocalPath -notmatch "\\Default$|\\Public$|\\All Users$" 
}

$TotalSkipped = 0
$TotalDeleted = 0
$TotalProcessed = 0

foreach ($Profile in $UserProfiles) {
    $UserSID = $Profile.SID
    $ProfilePath = $Profile.LocalPath
    $Username = Split-Path $ProfilePath -Leaf
    
    Write-Log "Processing user: $Username (SID: $UserSID)"
    
    try {
        # Load the user's registry hive if not already loaded
        $HiveLoaded = $false
        $UserHivePath = "$ProfilePath\NTUSER.DAT"
        
        if (Test-Path $UserHivePath) {
            # Check if hive is already loaded
            $ExistingHive = Get-ChildItem "Registry::HKEY_USERS" | Where-Object { $_.Name -eq "HKEY_USERS\$UserSID" }
            
            if (-not $ExistingHive) {
                Write-Log "  Loading user hive for $Username"
                & reg load "HKU\$UserSID" "$UserHivePath" 2>$null
                $HiveLoaded = $true
                Start-Sleep -Seconds 2
            }
        }
        
        # Access user's certificate store
        $UserCertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
        
        # Use the user's context by temporarily impersonating
        $UserStoreLocation = "Cert:\Users\$UserSID\My"
        
        # Alternative approach: directly access the registry-based store
        try {
            $Certificates = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue
            
            # If that doesn't work, try the registry path
            if (-not $Certificates) {
                $RegPath = "Registry::HKEY_USERS\$UserSID\SOFTWARE\Microsoft\SystemCertificates\My\Certificates"
                if (Test-Path $RegPath) {
                    Write-Log "  Accessing certificates via registry path"
                    $CertThumbprints = Get-ChildItem $RegPath -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName }
                    
                    $Certificates = @()
                    foreach ($Thumbprint in $CertThumbprints) {
                        try {
                            $CertPath = "Registry::HKEY_USERS\$UserSID\SOFTWARE\Microsoft\SystemCertificates\My\Certificates\$Thumbprint"
                            $BlobData = Get-ItemProperty -Path $CertPath -Name "Blob" -ErrorAction SilentlyContinue
                            if ($BlobData) {
                                $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                                $Cert.Import([byte[]]$BlobData.Blob)
                                $Certificates += $Cert
                            }
                        }
                        catch {
                            Write-Log "    Warning: Could not load certificate $Thumbprint"
                        }
                    }
                }
            }
        }
        catch {
            Write-Log "  Error accessing certificate store: $($_.Exception.Message)"
            continue
        }
        
        if ($Certificates) {
            Write-Log "  Found $($Certificates.Count) certificates"
            
            foreach ($Cert in $Certificates) {
                $TotalProcessed++
                $Subject = $Cert.Subject
                $Thumbprint = $Cert.Thumbprint
                
                $Issuer = $Cert.Issuer
                Write-Log "  Checking certificate: $Subject (Issuer: $Issuer) (Thumbprint: $Thumbprint)"
                
                # First check if issuer contains "Your Cert Issuer name - this should be the name of your cert authority"
                if ($Issuer -notlike "*My Cert Authority - Change me*") {
                    Write-Log "    Certificate issuer does not contain 'My Cert Authority' - SKIPPING"
                    $TotalSkipped++
                    continue
                }
                
                Write-Log "    Certificate issuer contains 'My Cert Authority' - proceeding with SAN check"
                $HasMicrosoftSAN = Test-MicrosoftSAN -Certificate $Cert
                
                if (-not $HasMicrosoftSAN) {
                    Write-Log "    Certificate does not contain microsoft.com in SAN - DELETING"
                    
                    try {
                        # Remove from registry if accessed that way
                        $RegCertPath = "Registry::HKEY_USERS\$UserSID\SOFTWARE\Microsoft\SystemCertificates\My\Certificates\$Thumbprint"
                        if (Test-Path $RegCertPath) {
                            Remove-Item -Path $RegCertPath -Recurse -Force
                            Write-Log "    Successfully deleted certificate from registry"
                            $TotalDeleted++
                        }
                        else {
                            # Try standard certificate store removal
                            $UserCertStore.Open("ReadWrite")
                            $UserCertStore.Remove($Cert)
                            $UserCertStore.Close()
                            Write-Log "    Successfully deleted certificate from store"
                            $TotalDeleted++
                        }
                    }
                    catch {
                        Write-Log "    ERROR: Failed to delete certificate - $($_.Exception.Message)"
                    }
                }
                else {
                    Write-Log "    Certificate contains microsoft.com in SAN - KEEPING"
                }
            }
        }
        else {
            Write-Log "  No certificates found in user store"
        }
        
        # Unload hive if we loaded it
        if ($HiveLoaded) {
            Write-Log "  Unloading user hive for $Username"
            & reg unload "HKU\$UserSID" 2>$null
        }
    }
    catch {
        Write-Log "  ERROR processing user $Username`: $($_.Exception.Message)"
    }
}

Write-Log "Certificate cleanup completed"
Write-Log "Total certificates found: $($TotalProcessed + $TotalSkipped)"
Write-Log "Total certificates with 'My Cert Authority' issuer: $TotalProcessed"
Write-Log "Total certificates skipped (no 'My Cert Authority' issuer): $TotalSkipped"
Write-Log "Total certificates deleted: $TotalDeleted"
Write-Log "Log file saved to: $LogFile"


# Trigger Intune device sync if any certificates were deleted
if ($TotalDeleted -gt 0) {
    Write-Log ""
    Write-Log "Certificates were deleted - initiating Intune device sync..."
    
    try {
        # Check if device is Intune enrolled
        $EnrollmentStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\*" -Name "ProviderID" -ErrorAction SilentlyContinue | Where-Object { $_.ProviderID -eq "MS DM Server" }
        
        if ($EnrollmentStatus) {
            Write-Log "  Device appears to be Intune enrolled - attempting sync"
            
            $IntuneSync = $false
            
            # Method 1: Try using dsregcmd (most reliable for device sync)
            try {
                Write-Log "  Attempting device sync via dsregcmd..."
                
                $dsregcmd = Get-Command "dsregcmd.exe" -ErrorAction SilentlyContinue
                if ($dsregcmd) {
                    $syncResult = & dsregcmd.exe /sync 2>&1
                    Write-Log "  dsregcmd sync executed - Result: $syncResult"
                    $IntuneSync = $true
                }
                else {
                    Write-Log "  dsregcmd.exe not found on system"
                }
            }
            catch {
                Write-Log "  dsregcmd sync failed: $($_.Exception.Message)"
            }
            
            # Method 2: Try triggering sync via Registry/WMI
            if (-not $IntuneSync) {
                try {
                    Write-Log "  Attempting Intune sync via MDM enrollment trigger..."
                    
                    $MDMSyncRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MDM"
                    if (Test-Path $MDMSyncRegPath) {
                        Set-ItemProperty -Path $MDMSyncRegPath -Name "LastSyncRequest" -Value (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") -Force
                        Write-Log "  MDM sync registry trigger set"
                    }
                    
                    $MDMDeviceRegistration = Get-WmiObject -Namespace "root\cimv2\mdm\dmmap" -Class "MDM_DeviceRegistrationInfo" -ErrorAction SilentlyContinue
                    if ($MDMDeviceRegistration) {
                        Write-Log "  Found MDM device registration - triggering sync"
                        Invoke-WmiMethod -Namespace "root\cimv2\mdm\dmmap" -Class "MDM_DeviceRegistrationInfo" -Name "SyncML" -ErrorAction SilentlyContinue
                    }
                    
                    $IntuneSync = $true
                }
                catch {
                    Write-Log "  Registry/WMI sync method failed: $($_.Exception.Message)"
                }
            }
            
            # Method 3: Try using ScheduledTask for IME sync
            if (-not $IntuneSync) {
                try {
                    Write-Log "  Checking for Intune Management Extension scheduled tasks..."
                    
                    $IntuneTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*Intune*" -or $_.TaskName -like "*MDM*" }
                    if ($IntuneTasks) {
                        Write-Log "  Found $($IntuneTasks.Count) Intune-related scheduled tasks"
                        foreach ($task in $IntuneTasks) {
                            if ($task.TaskName -like "*PushLaunch*" -or $task.TaskName -like "*Sync*") {
                                try {
                                    Start-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
                                    Write-Log "    Started task: $($task.TaskName)"
                                    $IntuneSync = $true
                                    break
                                }
                                catch {
                                    Write-Log "    Failed to start task $($task.TaskName): $($_.Exception.Message)"
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Log "  Scheduled task method failed: $($_.Exception.Message)"
                }
            }
            
            # Method 4: Try direct IME service restart (last resort)
            if (-not $IntuneSync) {
                try {
                    Write-Log "  Attempting to restart Intune Management Extension service..."
                    $IMEService = Get-Service -Name "IntuneManagementExtension" -ErrorAction SilentlyContinue
                    if ($IMEService) {
                        if ($IMEService.Status -eq "Running") {
                            Restart-Service -Name "IntuneManagementExtension" -Force -ErrorAction SilentlyContinue
                            Write-Log "  Intune Management Extension service restarted"
                        }
                        else {
                            Start-Service -Name "IntuneManagementExtension" -ErrorAction SilentlyContinue
                            Write-Log "  Intune Management Extension service started"
                        }
                        $IntuneSync = $true
                    }
                    else {
                        Write-Log "  Intune Management Extension service not found"
                    }
                }
                catch {
                    Write-Log "  IME service restart failed: $($_.Exception.Message)"
                }
            }
            
            if ($IntuneSync) {
                Write-Log "  Intune device sync initiated successfully"
                Write-Log "  Note: It may take several minutes for the sync to complete and new certificates to be deployed"
            }
            else {
                Write-Log "  Warning: Unable to trigger Intune sync - device may need manual sync"
            }
        }
        else {
            Write-Log "  Device does not appear to be Intune enrolled - skipping sync"
        }
    }
    catch {
        Write-Log "  Error during Intune sync process: $($_.Exception.Message)"
    }
}
else {
    Write-Log ""
    Write-Log "No certificates were deleted - skipping Intune device sync"
}

Write-Log ""
Write-Log "Script execution completed"