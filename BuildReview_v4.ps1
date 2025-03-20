# Author: Steve Velcev
# Date: 24/01/2025
# Version: 4.0.5
# Codename: VulnDup&IPSelection
# Description:  A Script that performs a windows operating system build review, with support for local and remote audit modes, automatic systeminfo parsing, user context-based questions, and the ability to skip questions.

##############################################
# Global Variables

$script:vulnerabilities = @()
$script:ReportFindingText = ""
$script:VMCheck = $false
$script:UserContext = "Standard User" # Default context; dynamically updated
$script:AuditMode = "" # Set dynamically to "Local" or "Remote"
$script:SystemType = "" # Set dynamically to either "VM" or "Physical"
$script:BuildType = "" # Set dynamically to "Workstation" or "Server"
$script:UserName = "" # Username of the account performing the checks
$script:ParsedHostname = ""
$script:ParsedSystemIPs = @()
$script:OperatingSystem = ""
$script:Manufacturer = ""
$script:Model = ""
$script:AskedQuestions = @()


# Define questions as a data structure
$script:Questions = @(
    @{ Id = 1; Question = "Is UAC enabled?"; ExpectedAnswer = "y"; VulnID = "SC-3302"; Description = "Check if User Account Control (UAC) is enabled."; CommandHint = "Get-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA"; GoodValue = "EnableLUA=1"; BadValue = "EnableLUA=0"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 2; Question = "Is the firewall enabled for public networks?"; ExpectedAnswer = "y"; VulnID = "SC-1996"; Description = "Ensure the firewall is enabled for public networks."; CommandHint = "Get-NetFirewallProfile -Profile Public"; GoodValue = "Enabled=True"; BadValue = "Enabled=False"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 3; Question = "Is BitLocker enabled on the primary drive?"; ExpectedAnswer = "y"; VulnID = "SC-2210"; Description = "Check if BitLocker is enabled on the primary drive."; CommandHint = "manage-bde -status"; GoodValue = "Protection On"; BadValue = "Protection Off"; AppliesTo = "Both"; SystemType = "Physical"; ExecutionContext = "Both" },
    @{ Id = 4; Question = "Is there a BIOS/UEFI password set?"; ExpectedAnswer = "y"; VulnID = "SC-1456"; Description = "The BIOS/UEFI should be protected by a password to prevent unauthorized modifications."; CommandHint = ""; GoodValue = "BIOS Password Set"; BadValue = "No BIOS Password"; AppliesTo = "Both"; SystemType = "Physical"; ExecutionContext = "Both" },
    @{ Id = 5; Question = "Is the BIOS password a default or weak password?"; ExpectedAnswer = "n"; VulnID = "SC-1952"; Description = "The BIOS/UEFI password should not be a default or easily guessable value."; CommandHint = ""; GoodValue = "Strong Custom Password"; BadValue = "Default/Weak Password"; AppliesTo = "Both"; SystemType = "Physical"; ExecutionContext = "Both" },
    @{ Id = 6; Question = "Can the boot order be changed without authentication?"; ExpectedAnswer = "n"; VulnID = "SC-1812"; Description = "Boot order changes should require authentication to prevent unauthorized boot device selection."; CommandHint = ""; GoodValue = "Authentication Required"; BadValue = "No Authentication Required"; AppliesTo = "Both"; SystemType = "Physical"; ExecutionContext = "Both" },
    @{ Id = 7; Question = "Can you log on to the server as a standard user?"; ExpectedAnswer = "n"; VulnID = "SC-3319"; Description = "Standard users should not be able to log on to the server to prevent unauthorized access."; CommandHint = "Attempt to log in with a standard user account"; GoodValue = "Logon Denied"; BadValue = "Logon Successful"; AppliesTo = "Server"; SystemType = "Both"; ExecutionContext = "Standard" },
    @{ Id = 8; Question = "Can you elevate to local Administrator privileges?"; ExpectedAnswer = "n"; VulnID = "SC-1583"; Description = "Standard users should not be able to elevate privileges to prevent unauthorized administrative access."; CommandHint = "Get-LocalGroupMember -Group 'Administrators'"; GoodValue = "User not in admin group"; BadValue = "User in admin group"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Standard" },
    @{ Id = 9; Question = "Can you access the C: drive in Windows Explorer?"; ExpectedAnswer = "n"; VulnID = "SC-2098"; Description = "Standard users should not have unrestricted access to the C: drive."; CommandHint = "Attempt to access C: drive via File Explorer"; GoodValue = "Access Denied"; BadValue = "Access Granted"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Standard" },
    @{ Id = 10; Question = "Can you access the Command prompt?"; ExpectedAnswer = "n"; VulnID = "SC-1632"; Description = "Standard users should not have access to the command prompt."; CommandHint = "Try running cmd.exe"; GoodValue = "Access Denied"; BadValue = "Access Granted"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 11; Question = "Can you access PowerShell or PowerShell ISE?"; ExpectedAnswer = "n"; VulnID = "SC-2074"; Description = "Standard users should not have unrestricted access to PowerShell or PowerShell ISE."; CommandHint = "Try running powershell.exe and powershell_ise.exe"; GoodValue = "Access Denied"; BadValue = "Access Granted"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 12; Question = "Is PowerShell Constrained Language Mode enabled?"; ExpectedAnswer = "y"; VulnID = "SC-2074"; Description = "PowerShell should be configured to use Constrained Language Mode to limit attack surface."; CommandHint = "$ExecutionContext.SessionState.LanguageMode"; GoodValue = "ConstrainedLanguage"; BadValue = "FullLanguage"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 13; Question = "Is PowerShell execution policy set to RemoteSigned or stricter?"; ExpectedAnswer = "y"; VulnID = "SC-2074"; Description = "PowerShell execution policy should be set to RemoteSigned or stricter."; CommandHint = "Get-ExecutionPolicy -List"; GoodValue = "RemoteSigned, AllSigned, or Restricted"; BadValue = "Unrestricted or Bypass"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 14; Question = "Can you disable the anti-virus solution?"; ExpectedAnswer = "n"; VulnID = "SC-1751"; Description = "Ensure antivirus cannot be disabled by administrative users."; CommandHint = "Check services.msc and attempt to stop antivirus services"; GoodValue = "Cannot disable AV"; BadValue = "AV can be disabled"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 15; Question = "Can you access malicious or inappropriate websites?"; ExpectedAnswer = "n"; VulnID = "SC-1746"; Description = "Ensure malicious sites are blocked for standard users."; CommandHint = "Test access to exploit-db.com, kitploit.com, shellterproject.com"; GoodValue = "Sites Blocked"; BadValue = "Sites Accessible"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 16; Question = "Can you access the Windows registry?"; ExpectedAnswer = "n"; VulnID = "SC-2095"; Description = "Standard users should not have access to the Windows registry."; CommandHint = "Try opening regedit.exe or Get-ItemProperty HKLM:\SOFTWARE"; GoodValue = "Registry Access Denied"; BadValue = "Registry Accessible"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Standard" },
    @{ Id = 17; Question = "Do standard users have dangerous user privileges?"; ExpectedAnswer = "n"; VulnID = "SC-1847"; Description = "Standard users should not have elevated privileges like Debug or Take Ownership."; CommandHint = "whoami /priv | findstr /i 'SeDebug SeTakeOwnership SeRestore SeBackup'"; GoodValue = "No Dangerous Privileges"; BadValue = "Dangerous Privileges Present"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Standard" },
    @{ Id = 18; Question = "Is an antivirus solution installed and up-to-date?"; ExpectedAnswer = "y"; VulnID = "SC-1680"; Description = "Ensure an antivirus solution is installed and current."; CommandHint = "Get-MpComputerStatus # for Windows Defender, or check third-party AV"; GoodValue = "AV Installed and Updated"; BadValue = "No AV or Outdated"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 19; Question = "Can Domain Admins log into the system?"; ExpectedAnswer = "n"; VulnID = "SC-3341"; Description = "Domain Admin accounts should not be allowed to log into member servers/workstations."; CommandHint = "net localgroup administrators | findstr 'Domain Admins'"; GoodValue = "Domain Admins not in administrators group"; BadValue = "Domain Admins in administrators group"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 20; Question = "Is the screen lockout period 5 minutes or less?"; ExpectedAnswer = "y"; VulnID = "SC-2229"; Description = "Ensure an screen inactivity lockout policy of 5 minutes or less is configured."; CommandHint = "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs"; GoodValue = "Timeout ≤ 300 seconds"; BadValue = "Timeout > 300 seconds or not set"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 21; Question = "Is LAPS installed?"; ExpectedAnswer = "y"; VulnID = "SC-3580"; Description = "Ensure LAPS is installed to secure local administrator credentials."; CommandHint = "Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS\Config' -ErrorAction SilentlyContinue"; GoodValue = "LAPS Installed"; BadValue = "LAPS Not Installed"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 22; Question = "Is the Local Administrator password unique across the network?"; ExpectedAnswer = "y"; VulnID = "SC-1927"; Description = "Ensure unique local administrator passwords are used."; CommandHint = ""; GoodValue = "Unique Password"; BadValue = "Shared Password"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 23; Question = "Does the system allow SSH connections?"; ExpectedAnswer = "n"; VulnID = "SC-7401"; Description = "Ensure SSH connections are disabled unless explicitly required."; CommandHint = "Test-NetConnection -Port 22"; GoodValue = "SSH Disabled/Blocked"; BadValue = "SSH Enabled/Accessible"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 24; Question = "Are cached domain logon credentials set to 0 or 1?"; ExpectedAnswer = "y"; VulnID = "SC-6278"; Description = "Ensure cached domain credentials are limited."; CommandHint = "(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').CachedLogonsCount"; GoodValue = "CachedLogonsCount ≤ 1"; BadValue = "CachedLogonsCount > 1"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 25; Question = "Is Kernel DMA Protection enabled?"; ExpectedAnswer = "y"; VulnID = "SC-6113"; Description = "Ensure Kernel DMA Protection is enabled to mitigate Direct Memory Access attacks."; CommandHint = "Get-SystemDriver -DMAProtection | Select-Object DMAProtectionStatus"; GoodValue = "DMA Protection: On"; BadValue = "DMA Protection: Off"; AppliesTo = "Both"; SystemType = "Physical"; ExecutionContext = "Both" },
    @{ Id = 26; Question = "Is BitLocker pre-boot authentication enabled?"; ExpectedAnswer = "y"; VulnID = "SC-5948"; Description = "Verify that BitLocker pre-boot authentication is configured."; CommandHint = "manage-bde -status"; GoodValue = "Pre-Boot Authentication Enabled"; BadValue = "Pre-Boot Authentication Disabled"; AppliesTo = "Both"; SystemType = "Physical"; ExecutionContext = "Both" },
    @{ Id = 27; Question = "Is IOMMU (VT-d/AMD-Vi) enabled in BIOS?"; ExpectedAnswer = "y"; VulnID = "SC-6114"; Description = "Ensure IOMMU is enabled to prevent unauthorized I/O transactions."; CommandHint = "Check BIOS settings"; GoodValue = "IOMMU Enabled"; BadValue = "IOMMU Disabled"; AppliesTo = "Both"; SystemType = "Physical"; ExecutionContext = "Both" },
    @{ Id = 28; Question = "Is the built-in Administrator account (RID 500) disabled?"; ExpectedAnswer = "y"; VulnID = "SC-4958"; Description = "The built-in Administrator account should be disabled to prevent its misuse."; CommandHint = "Get-LocalUser | Where-Object { $_.SID -Like '*-500' } | Select-Object Name,Enabled"; GoodValue = "Account Disabled"; BadValue = "Account Enabled"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 29; Question = "Is the FilterAdministratorToken policy enabled?"; ExpectedAnswer = "y"; VulnID = "SC-6311"; Description = "The FilterAdministratorToken policy should be enabled."; CommandHint = "Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken'"; GoodValue = "FilterAdministratorToken=1"; BadValue = "FilterAdministratorToken=0 or not set"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 30; Question = "Is the LocalAccountTokenFilterPolicy disabled?"; ExpectedAnswer = "y"; VulnID = "SC-6312"; Description = "The LocalAccountTokenFilterPolicy should be disabled."; CommandHint = "Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue"; GoodValue = "Policy not set or set to 0"; BadValue = "Policy set to 1"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 31; Question = "Can non-malicious executables be downloaded and executed by standard users?"; ExpectedAnswer = "n"; VulnID = "SC-2162"; Description = "Standard users should not be able to download and execute applications."; CommandHint = "Test with known good software installation attempt"; GoodValue = "Execution Blocked"; BadValue = "Execution Allowed"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Standard" },
    @{ Id = 32; Question = "Is Windows Defender configured with appropriate exclusions?"; ExpectedAnswer = "y"; VulnID = "SC-1755"; Description = "Windows Defender should not have overly broad exclusions configured."; CommandHint = "Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess"; GoodValue = "Minimal necessary exclusions"; BadValue = "Broad or unnecessary exclusions"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 33; Question = "Can standard users read from USB devices?"; ExpectedAnswer = "n"; VulnID = "SC-2170"; Description = "Standard users should not have read access to USB devices unless required."; CommandHint = "Test USB device read access with standard user"; GoodValue = "USB Read Access Denied"; BadValue = "USB Read Access Allowed"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Standard" },
    @{ Id = 34; Question = "Can standard users write to USB devices?"; ExpectedAnswer = "n"; VulnID = "SC-2170"; Description = "Standard users should not have write access to USB devices unless required."; CommandHint = "Test USB device write access with standard user"; GoodValue = "USB Write Access Denied"; BadValue = "USB Write Access Allowed"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Standard" },
    @{ Id = 35; Question = "Are Thunderbolt ports protected by security policy?"; ExpectedAnswer = "y"; VulnID = "SC-6114"; Description = "Thunderbolt ports should be protected by appropriate security policies to prevent DMA attacks."; CommandHint = "Check BIOS/UEFI settings for Thunderbolt security policy level"; GoodValue = "Security Level 1 or higher"; BadValue = "No security or Level 0"; AppliesTo = "Both"; SystemType = "Physical"; ExecutionContext = "Both" },
    @{ Id = 36; Question = "Is Secure Boot enabled?"; ExpectedAnswer = "y"; VulnID = "SC-6114"; Description = "Secure Boot should be enabled to prevent unauthorized boot code execution."; CommandHint = "Confirm-SecureBootUEFI"; GoodValue = "Secure Boot Enabled"; BadValue = "Secure Boot Disabled"; AppliesTo = "Both"; SystemType = "Physical"; ExecutionContext = "Administrative" },
    @{ Id = 37; Question = "Are Microsoft Virtualization-Based Security (VBS) features enabled?"; ExpectedAnswer = "y"; VulnID = "SC-7499"; Description = "VBS features like Credential Guard should be enabled to protect against credential theft."; CommandHint = "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"; GoodValue = "VBS Features Active"; BadValue = "VBS Features Inactive"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 38; Question = "Do any local folders contain plain text passwords?"; ExpectedAnswer = "n"; VulnID = "SC-1613"; Description = "Check for plain text passwords in local folders and mounted shares."; CommandHint = "Manual review of accessible folders required"; GoodValue = "No plain text credentials found"; BadValue = "Plain text credentials found"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 39; Question = "Is Nearby Sharing enabled?"; ExpectedAnswer = "n"; VulnID = "SC-6410"; Description = "Ensure Nearby Sharing is disabled to prevent data leakage."; CommandHint = "Check Windows Settings > System > Shared Experiences"; GoodValue = "Nearby Sharing Disabled"; BadValue = "Nearby Sharing Enabled"; AppliesTo = "Workstation"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 40; Question = "Is there software restriction policies configured?"; ExpectedAnswer = "y"; VulnID = "SC-2162"; Description = "Ensure software restriction policies are configured to limit unauthorized executable files."; CommandHint = "Get-AppLockerPolicy -Effective -Xml"; GoodValue = "Policies Configured"; BadValue = "No Policies Found"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 41; Question = "Is the Guest account disabled?"; ExpectedAnswer = "y"; VulnID = "SC-3001"; Description = "Ensure the Guest account is disabled to prevent unauthorized access."; CommandHint = "Get-LocalUser | Where-Object { $_.Name -eq 'Guest' }"; GoodValue = "Guest Account Disabled"; BadValue = "Guest Account Enabled"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 42; Question = "Is Remote Desktop disabled for standard users?"; ExpectedAnswer = "y"; VulnID = "SC-1756"; Description = "Ensure Remote Desktop is disabled for standard users."; CommandHint = "Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections"; GoodValue = "RDP Disabled for Standard Users"; BadValue = "RDP Enabled for Standard Users"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 43; Question = "Does the server have the same anti-virus solution as the workstation?"; ExpectedAnswer = "n"; VulnID = "SC-1851"; Description = "Verify that the server has a different anti-virus solution than the workstation to avoid shared vulnerabilities."; CommandHint = "Compare installed antivirus solutions on server and workstation"; GoodValue = "Different antivirus solutions"; BadValue = "Same antivirus solution"; AppliesTo = "Server"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 44; Question = "Does the server allow internet access?"; ExpectedAnswer = "n"; VulnID = "SC-3533"; Description = "Ensure that the server does not allow internet access to minimize security risks."; CommandHint = "Test internet access by browsing or using Test-NetConnection"; GoodValue = "No internet access"; BadValue = "Internet access available"; AppliesTo = "Server"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 45; Question = "Does the server contain a database and a web server?"; ExpectedAnswer = "n"; VulnID = "SC-1661"; Description = "Ensure that the server does not host both database and web server roles without sufficient segregation."; CommandHint = "Inspect server roles and services running on the server"; GoodValue = "Roles are segregated"; BadValue = "Roles are not segregated"; AppliesTo = "Server"; SystemType = "Both"; ExecutionContext = "Both" },
    @{ Id = 46; Question = "Can the local user hashes be extracted?"; ExpectedAnswer = "n"; VulnID = "SC-3342"; Description = "Ensure that local user hashes cannot be extracted using tools like Mimikatz or similar methods."; CommandHint = "Attempt hash extraction using common tools or techniques"; GoodValue = "Hashes cannot be extracted"; BadValue = "Hashes can be extracted"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Administrative" },
    @{ Id = 47; Question = "Can browser extensions be installed?"; ExpectedAnswer = "n"; VulnID = "SC-7829"; Description = "Ensure that non-vetted browser extensions cannot be installed."; CommandHint = "For each default-installed browser, attempt to install a browser extension such as a game or other non-work-related application."; GoodValue = "Browser extensions cannot be installed"; BadValue = "Browser extensions can be installed"; AppliesTo = "Both"; SystemType = "Both"; ExecutionContext = "Both" }
)

##############################################
# Functions

Function AddVulnText ($VulnID, $Text, $Context) {
    # Determine the username based on the context
    $username = if ($Context -eq "Administrative" -and $script:AdminUserName) {
        $script:AdminUserName
    } elseif ($script:UserName) {
        $script:UserName
    } else {
        "Unknown User"
    }

    # Check if the vulnerability ID already exists in the array
    $existingVuln = $script:vulnerabilities | Where-Object { $_.VulnID -eq $VulnID }
    
    if ($existingVuln) {
        # Append the new description to the existing entry
        $existingVuln.Information += "`n$Text (Executed as $Context user, Username: $username)"
    } else {
        # Create a new structured vulnerability entry
        $newVuln = [PSCustomObject]@{
            VulnID = $VulnID
            Information = "$Text (Executed as $Context user, Username: $username)"
        }
        $script:vulnerabilities += $newVuln
    }

    # Add to human-readable report
    $script:ReportFindingText += "- $Text (Executed as $Context user, Username: $username)`n"
}


# Ensure the SC-1707 Build Review vulnerability is always added
Function EnsureBaseVulnerability {
    param (
        [string]$IPAddress,
        [string]$Hostname,
        [string]$OperatingSystem,
        [string]$Manufacturer,
        [string]$Model,
        [string]$UserAccount
    )

    $BaseDescription = @"
A build review of the provided system was performed to assess it against current industry best security practices.

|Description|Value|
|----|----|
|IP Address:|$IPAddress|
|Hostname:|$Hostname|
|Operating System:|$OperatingSystem|
|Manufacturer:|$Manufacturer|
|Model:|$Model|
|User Account:|$UserAccount|

The following findings were noted:
"@
    
    # Append all vulnerabilities as a list
    foreach ($vuln in $script:vulnerabilities) {
        $BaseDescription += "- $($vuln.Information)`n"
    }
    
    AddVulnText -VulnID "SC-1707" -Text $BaseDescription -Context "System Review"
}


# Function to extract IP addresses from systeminfo output
Function Get-SystemIPs {
    param (
        [Parameter(Mandatory=$false)]
        [string[]]$SystemInfoOutput
    )

    # Prompt for IPv6 inclusion
    $includeIPv6 = Read-Host "Do you want to include IPv6 addresses? (Y/N)" |
        ForEach-Object { $_.ToLower() }
    $includeIPv6 = if ($includeIPv6 -eq "y") { $true } elseif ($includeIPv6 -eq "n") { $false } else { $false }

    # Initialize array for IP addresses
    $ipAddresses = @()

    try {
        # Method 1: Try to find IP Address(es) section
        $ipSection = $SystemInfoOutput | Select-String -Pattern "IP Address" -Context 0,10
        if ($ipSection) {
            # Extract IPv4 addresses using regex
            $ipv4Regex = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
            $ipAddresses += [regex]::Matches($ipSection, $ipv4Regex) |
                ForEach-Object { $_.Value } |
                Where-Object { $_ -ne "127.0.0.1" } # Exclude localhost

            # Extract IPv6 addresses if selected
            if ($includeIPv6) {
                $ipv6Regex = '\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'
                $ipAddresses += [regex]::Matches($ipSection, $ipv6Regex) |
                    ForEach-Object { $_.Value }
            }
        }

        # Fallback Method: Use Get-NetIPAddress if available and we're running locally
        if (-not $ipAddresses -and (Get-Command 'Get-NetIPAddress' -ErrorAction SilentlyContinue)) {
            Write-Verbose "Using Get-NetIPAddress as fallback"
            $ipAddresses += Get-NetIPAddress -AddressFamily IPv4 |
                Where-Object { $_.IPAddress -ne "127.0.0.1" } |
                Select-Object -ExpandProperty IPAddress
            if ($includeIPv6) {
                $ipAddresses += Get-NetIPAddress -AddressFamily IPv6 |
                    Select-Object -ExpandProperty IPAddress
            }
        }

        # Remove duplicates and sort
        $ipAddresses = $ipAddresses | Select-Object -Unique | Sort-Object

        # If we still have no IPs, try one final broad search
        if (-not $ipAddresses) {
            Write-Verbose "Performing full content search for IP addresses"
            $ipv4Regex = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
            $ipAddresses = [regex]::Matches(($SystemInfoOutput | Out-String), $ipv4Regex) |
                ForEach-Object { $_.Value } |
                Where-Object { $_ -ne "127.0.0.1" } |
                Select-Object -Unique |
                Sort-Object
            if ($includeIPv6) {
                $ipv6Regex = '\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'
                $ipAddresses += [regex]::Matches(($SystemInfoOutput | Out-String), $ipv6Regex) |
                    ForEach-Object { $_.Value } |
                    Select-Object -Unique |
                    Sort-Object
            }
        }

        return $ipAddresses
    }
    catch {
        Write-Warning "Error extracting IP addresses: $_"
        return $null
    }
}

Function ParseSystemInfo {
    if ($script:AuditMode -eq "remote") {
        $useFile = Read-Host "Do you have a systeminfo.txt file to parse? (y/n)"
        if ($useFile -eq "y") {
            if (Test-Path -Path "systeminfo.txt") {
                $systemInfo = Get-Content -Path "systeminfo.txt" -Raw
            } else {
                Write-Output "systeminfo.txt file not found in the current directory. Switching to manual entry."
                $useFile = "n"
            }
        }
        if ($useFile -ne "y") {
            $script:OperatingSystem = Read-Host "Enter OS Version"
            $script:Manufacturer = Read-Host "Enter Manufacturer"
            $script:Model = Read-Host "Enter Model"
            $script:ParsedHostname = Read-Host "Enter Hostname"
            $script:ParsedSystemIPs = @(Read-Host "Enter IP Address(es), separated by commas")
        }
    } else {
        $systemInfo = & systeminfo
    }

    if ($systemInfo) {
        # Extract details from systeminfo output
        $script:OperatingSystem = ($systemInfo | Select-String -Pattern "OS Name\s*:\s*(.+)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() })
        $script:Manufacturer = ($systemInfo | Select-String -Pattern "System Manufacturer\s*:\s*(.+)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() })
        $script:Model = ($systemInfo | Select-String -Pattern "System Model\s*:\s*(.+)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() })
        $script:ParsedHostname = ($systemInfo | Select-String -Pattern "Host Name\s*:\s*(.+)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() })
        $script:ParsedSystemIPs = Get-SystemIPs -SystemInfoOutput $systemInfo
    }

    # Default fallback values if parsing failed
    if (-not $script:ParsedHostname) {
        Write-Warning "Hostname not found. Using default value 'Unknown-Host'."
        $script:ParsedHostname = "Unknown-Host"
    }
    if (-not $script:ParsedSystemIPs -or $script:ParsedSystemIPs.Count -eq 0) {
        Write-Warning "No IP addresses found. Using default IP address '127.0.0.1'."
        $script:ParsedSystemIPs = @("127.0.0.1")
    }

    # Format IP addresses for display
    $ipAddressDisplay = $script:ParsedSystemIPs -join ', '

    # Display system information
    Write-Output "### System Information ###"
    Write-Output "| Field          | Value                           |"
    Write-Output "|----------------|---------------------------------|"
    Write-Output "| OS Version     | $script:OperatingSystem         |"
    Write-Output "| Manufacturer   | $script:Manufacturer            |"
    Write-Output "| Model          | $script:Model                   |"
    Write-Output "| Hostname       | $script:ParsedHostname         |"
    Write-Output "| IP Addresses   | $ipAddressDisplay               |"
}


# AskQuestions Function
Function AskQuestions ($contextForExecution) {
    foreach ($q in $script:Questions) {
        # Skip questions already asked
        if ($script:AskedQuestions -contains $q.Id) {
            Write-Verbose "Skipping question $($q.Id) as it has already been asked."
            Continue
        }

        # Ensure the question matches the ExecutionContext
        if ($q.ExecutionContext -ne $contextForExecution -and $q.ExecutionContext -ne "Both") {
            Write-Verbose "Skipping question $($q.Id) due to ExecutionContext mismatch."
            Continue
        }

        # Ensure the question matches the BuildType
        if ($q.AppliesTo -ne $script:BuildType -and $q.AppliesTo -ne "Both") {
            Write-Verbose "Skipping question $($q.Id) due to BuildType mismatch."
            Continue
        }

        # Ensure the question matches the SystemType
        if ($q.SystemType -ne $script:SystemType -and $q.SystemType -ne "Both") {
            Write-Verbose "Skipping question $($q.Id) due to SystemType mismatch."
            Continue
        }

        # Output the question and details to the user
        Write-Output "### Question $($q.Id): $($q.Question) ###"
        Write-Output "Description: $($q.Description)"
        if ($q.CommandHint -ne "") {
            Write-Output "Hint: $($q.CommandHint)"
        }
        Write-Output "Good Value: $($q.GoodValue)"
        Write-Output "Bad Value: $($q.BadValue)"
        Write-Output "Executed as: $contextForExecution"

        # Prompt for user response
        do {
            $script:Query = Read-Host "$($q.Question) (y/n/skip)"
            $script:Query = $script:Query.ToLower()
        } until ($script:Query -in ("y", "n", "s", "skip"))

        # Handle user response
        if ($script:Query -eq "s" -or $script:Query -eq "skip") {
            Write-Verbose "User skipped question $($q.Id)."
            Continue
        } elseif ($script:Query -ne $q.ExpectedAnswer) {
            Write-Output "Incorrect answer detected for question $($q.Id). Adding to vulnerabilities."
            AddVulnText -VulnID $q.VulnID -Text "$($q.Description)" -Context $contextForExecution
        } else {
            Write-Verbose "User provided the correct answer for question $($q.Id)."
        }

        # Record the question as asked
        $script:AskedQuestions += @($q.Id)
    }
}


# Context Determination Function
Function DetermineContext {
    # Prompt for execution context
    Write-Output "### Context Determination ###"

    # 1. Prompt for local or remote execution
    do {
        Write-Output "Options: (L)ocal / (R)emote"
        $script:AuditMode = Read-Host "Will the script be executed on the device locally or is the script being run on a remote host? (L/R)" |
            ForEach-Object { $_.ToLower() }
        if ($script:AuditMode -notin @("local", "remote", "l", "r")) {
            Write-Output "Invalid input. Please enter 'L' for Local or 'R' for Remote."
        }
    } until ($script:AuditMode -in @("local", "remote", "l", "r"))
    $script:AuditMode = if ($script:AuditMode -eq "l") { "local" } elseif ($script:AuditMode -eq "r") { "remote" } else { $script:AuditMode }

    # 2. Prompt for server or workstation
    do {
        Write-Output "Options: (S)erver / (W)orkstation"
        $script:BuildType = Read-Host "Is it for a server or workstation? (S/W)" |
            ForEach-Object { $_.ToLower() }
        if ($script:BuildType -notin @("server", "workstation", "s", "w")) {
            Write-Output "Invalid input. Please enter 'S' for Server or 'W' for Workstation."
        }
    } until ($script:BuildType -in @("server", "workstation", "s", "w"))
    $script:BuildType = if ($script:BuildType -eq "s") { "server" } elseif ($script:BuildType -eq "w") { "workstation" } else { $script:BuildType }

    # 3. Prompt for physical or virtual machine
    do {
        Write-Output "Options: (P)hysical / (V)M"
        $script:SystemType = Read-Host "Is it for a physical device or virtual machine? (P/V)" |
            ForEach-Object { $_.ToLower() }
        if ($script:SystemType -notin @("physical", "vm", "p", "v")) {
            Write-Output "Invalid input. Please enter 'P' for Physical or 'V' for VM."
        }
    } until ($script:SystemType -in @("physical", "vm", "p", "v"))
    $script:SystemType = if ($script:SystemType -eq "p") { "physical" } elseif ($script:SystemType -eq "v") { "vm" } else { $script:SystemType }

   # 4. Prompt for execution as standard user or administrator
    do {
        Write-Output "Options: (S)tandard User / (A)dministrator"
        $script:UserContext = Read-Host "What are the tests being run as: Standard User or Administrator? (S/A)" |
            ForEach-Object { $_.ToLower() }
        if ($script:UserContext -notin @("standard", "administrative", "s", "a")) {
            Write-Output "Invalid input. Please enter 'S' for Standard User or 'A' for Administrator."
        }
    } until ($script:UserContext -in @("standard", "administrative", "s", "a"))
    $script:UserContext = if ($script:UserContext -eq "s") { "standard" } elseif ($script:UserContext -eq "a") { "administrative" } else { $script:UserContext }


    # 5. Prompt for the username of the account performing the checks
    do {
        $script:UserName = Read-Host "Enter the username of the account performing the checks (non-empty)"
        if (-not $script:UserName) {
            Write-Output "Invalid input. Username cannot be empty."
        }
    } until ($script:UserName -and $script:UserName -ne "")

    # Output summary of determined context
    Write-Output "### Execution Context Summary ###"
    Write-Output "- Audit Mode: $script:AuditMode"
    Write-Output "- Build Type: $script:BuildType"
    Write-Output "- System Type: $script:SystemType"
    Write-Output "- User Context: $script:UserContext"
    Write-Output "- Username: $script:UserName"
}


Function RunAudit {
    # Use the context determined in DetermineContext
    if ($script:UserContext -eq "standard") {
        Write-Output "Running checks for context: Standard User"
        AskQuestions -contextForExecution "Standard"

        # Prompt to execute administrative checks
        $continueAdminChecks = Read-Host "Would you like to perform administrative checks as well? (y/n)"
        if ($continueAdminChecks -eq "y") {
            $script:UserContext = "both"
            $script:AdminUserName = Read-Host "Enter the username for administrative checks"
            Write-Output "Running checks for context: Administrator"
            AskQuestions -contextForExecution "Administrative"
        }
    } elseif ($script:UserContext -eq "administrative") {
        Write-Output "Running checks for context: Administrator"
        $script:AdminUserName = Read-Host "Enter the username for administrative checks"
        AskQuestions -contextForExecution "Administrative"
    } else {
        Write-Output "Invalid user context detected. Exiting script."
        exit
    }
}

Function SaveResults {
    $timestamp = (Get-Date -Format "yyyyMMdd_HHmmss")
    $contextForFilename = $script:UserContext -replace "[^a-zA-Z0-9]", "" # Remove special characters for filename safety

    if ($script:UserContext -eq "both") {
        $contextForFilename = "standard_admin"
    }

    # Prompt user to select the main IP address from the found IPs
    if ($script:ParsedSystemIPs.Count -gt 1) {
        Write-Output "Multiple IP addresses found:"
        for ($i = 0; $i -lt $script:ParsedSystemIPs.Count; $i++) {
            Write-Output "[$i] $($script:ParsedSystemIPs[$i])"
        }
        do {
            $selection = Read-Host "Enter the number of the IP address to use"
        } while (-not ($selection -match "^\d+$") -or [int]$selection -lt 0 -or [int]$selection -ge $script:ParsedSystemIPs.Count)
        
        $ipAddress = $script:ParsedSystemIPs[[int]$selection]
    } else {
        $ipAddress = $script:ParsedSystemIPs[0]
    }
    $hostname = $script:ParsedHostname
    $operatingSystem = $script:OperatingSystem
    $manufacturer = $script:Manufacturer
    $model = $script:Model
    $userAccount = $script:UserName

    # Ensure the base vulnerability is always added
    EnsureBaseVulnerability -IPAddress $ipAddress -Hostname $hostname -OperatingSystem $operatingSystem -Manufacturer $manufacturer -Model $model -UserAccount $userAccount

    # Convert structured data to XML format for output
    $xmlVulnOutput = "<services>`n"
    foreach ($vuln in $script:vulnerabilities) {
        $xmlVulnOutput += "<service name='' port='' protocol='tcp'>`n"
        $xmlVulnOutput += "    <vulnerabilities>`n"
        $xmlVulnOutput += "        <vulnerability id='$($vuln.VulnID)'>`n"
        $xmlVulnOutput += "            <information>$($vuln.Information)</information>`n"
        $xmlVulnOutput += "        </vulnerability>`n"
        $xmlVulnOutput += "    </vulnerabilities>`n"
        $xmlVulnOutput += "</service>`n"
    }
    $xmlVulnOutput += "</services>"

    # Construct the XML content
    $xmlContent = @"
<?xml version='1.0' encoding='utf8'?>
<items source="SureFormat" version="1.0.0">
    <item ipaddress="$ipAddress" hostname="$hostname">
        $xmlVulnOutput
    </item>
</items>
"@

    # Define output filenames
    $xmlFile = "win_build_review_${contextForFilename}_$timestamp.xml"
    $textFile = "win_build_review_${contextForFilename}_$timestamp.txt"

    try {
        $xmlContent | Out-File -FilePath $xmlFile -Encoding UTF8
        Write-Output "XML results saved to: $xmlFile"
    } catch {
        Write-Output "Failed to save XML results."
    }

    try {
        $script:ReportFindingText | Out-File -FilePath $textFile -Encoding UTF8
        Write-Output "Text results saved to: $textFile"
    } catch {
        Write-Output "Failed to save text results."
    }
}


##############################################
# Main Execution Area

Write-Output "Starting Build Review Script..."

# Call DetermineContext to set execution context
DetermineContext

# Call ParseSystemInfo to extract system details
ParseSystemInfo

# Run the audit based on the selected context
RunAudit

# Save results
SaveResults
Write-Output "Build review completed. Results saved."
