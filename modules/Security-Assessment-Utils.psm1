# Security Assessment Utilities Module
# Contains connection functions, helper utilities, and shared variables

# Color coding for console output
$script:Colors = @{
    'Critical' = 'Red'
    'High' = 'Magenta' 
    'Medium' = 'Yellow'
    'Low' = 'Cyan'
    'Good' = 'Green'
    'Info' = 'White'
}

# Assessment results storage - using Global scope for cross-module access
$Global:AssessmentResults = @{
    'Critical' = @()
    'High' = @()
    'Medium' = @()
    'Low' = @()
    'Good' = @()
    'Info' = @()
}

# Essential 8 compliance tracking - using Global scope for cross-module access
$Global:Essential8Results = @{
    'ApplicationControl' = @()
    'PatchApplications' = @()
    'OfficeMacroSettings' = @()
    'UserApplicationHardening' = @()
    'RestrictAdminPrivileges' = @()
    'PatchOperatingSystems' = @()
    'MultiFactor' = @()
    'RegularBackups' = @()
}

# Required modules for the assessment
$script:RequiredModules = @(
    'Az.Accounts',
    'Az.Resources', 
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Reports',
    'Microsoft.Graph.DeviceManagement.Enrolment',
    'Microsoft.Graph.DeviceManagement.Actions',
    'Microsoft.Graph.Security'
)

function Test-RequiredModules {
    Write-Host "Checking required modules..." -ForegroundColor Cyan
    
    $missingModules = @()
    foreach ($module in $script:RequiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Host "Missing modules detected: $($missingModules -join ', ')" -ForegroundColor Yellow
        Write-Host "Running setup script to install missing modules..." -ForegroundColor Yellow
        
        # Check if setup script exists
        $setupScript = ".\setup-requirements.ps1"
        if (!(Test-Path $setupScript)) {
            Write-Error "Setup script not found: $setupScript"
            Write-Host "Please ensure setup-requirements.ps1 is in the same directory as this script." -ForegroundColor Red
            return $false
        }
        
        # Run setup script
        try {
            Write-Host "Executing: $setupScript" -ForegroundColor Gray
            & $setupScript
            
            # Verify modules are now installed
            $stillMissing = @()
            foreach ($module in $missingModules) {
                if (!(Get-Module -ListAvailable -Name $module)) {
                    $stillMissing += $module
                }
            }
            
            if ($stillMissing.Count -gt 0) {
                Write-Error "Failed to install modules: $($stillMissing -join ', ')"
                Write-Host "Please run setup-requirements.ps1 manually or install modules with:" -ForegroundColor Red
                Write-Host "Install-Module -Name $($stillMissing -join ', ') -Scope CurrentUser" -ForegroundColor Gray
                return $false
            }
            
            Write-Host "All required modules are now installed!" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to run setup script: $_"
            return $false
        }
    } else {
        Write-Host "All required modules are available!" -ForegroundColor Green
    }
    
    return $true
}

function Write-AssessmentResult {
    param(
        [string]$Category,
        [string]$Finding,
        [string]$Severity,
        [string]$Recommendation = "",
        [string]$Details = ""
    )
    
    $result = @{
        Category = $Category
        Finding = $Finding
        Severity = $Severity
        Recommendation = $Recommendation
        Details = $Details
        Timestamp = Get-Date
    }
    
    $Global:AssessmentResults[$Severity] += $result
    
    $color = $script:Colors[$Severity]
    Write-Host "[$Severity] ${Category}: $Finding" -ForegroundColor $color
    if ($Recommendation) {
        Write-Host "  -> Recommendation: $Recommendation" -ForegroundColor Gray
    }
    if ($DetailedOutput -and $Details) {
        Write-Host "  -> Details: $Details" -ForegroundColor Gray
    }
}

function Connect-ToAzureServices {
    Write-Host "`n=== Connecting to Azure Services ===" -ForegroundColor Cyan
    
    # Check for conflicting modules
    Write-Host "Checking for module conflicts..." -ForegroundColor Yellow
    $azureRMModules = Get-Module -ListAvailable -Name AzureRM*
    if ($azureRMModules.Count -gt 0) {
        Write-Host "WARNING: AzureRM modules detected. These can conflict with Az modules." -ForegroundColor Red
        Write-Host "Consider removing AzureRM modules: Uninstall-AzureRm" -ForegroundColor Yellow
    }
    
    # Disconnect any existing sessions to ensure clean connection
    try {
        Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Ignore errors when disconnecting
    }
    
    # Import required modules explicitly
    try {
        Write-Host "Importing Az.Accounts module..." -ForegroundColor Yellow
        Import-Module Az.Accounts -Force -ErrorAction Stop
        
        Write-Host "Importing Microsoft.Graph.Authentication module..." -ForegroundColor Yellow
        Import-Module Microsoft.Graph.Authentication -Force -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to import required modules: $_"
        return $false
    }
    
    # Connect to Azure with interactive browser authentication
    try {
        Write-Host "Connecting to Azure..." -ForegroundColor Yellow
        Write-Host "A browser window will open for authentication..." -ForegroundColor Gray
        
        $azContext = Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to Azure as $($azContext.Context.Account.Id)" -ForegroundColor Green
        
        # Get tenant information
        $tenantInfo = Get-AzTenant | Select-Object -First 1
        if ($tenantInfo) {
            Write-Host "Tenant: $($tenantInfo.Name) ($($tenantInfo.Id))" -ForegroundColor Green
            
                    # Store tenant info globally for report generation
        $Global:TenantName = $tenantInfo.Name
        $Global:TenantId = $tenantInfo.Id
        }
        
    }
    catch {
        Write-Error "Failed to connect to Azure: $_"
        Write-Host "Troubleshooting steps:" -ForegroundColor Yellow
        Write-Host "1. Ensure you have the latest Az modules: Update-Module Az" -ForegroundColor Gray
        Write-Host "2. Clear any cached credentials: Clear-AzContext -Force" -ForegroundColor Gray
        Write-Host "3. Remove conflicting modules: Uninstall-AzureRm" -ForegroundColor Gray
        return $false
    }
    
    # Connect to Microsoft Graph
    try {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        $graphScopes = @(
            'Directory.Read.All',
            'Policy.Read.All', 
            'UserAuthenticationMethod.Read.All',
            'IdentityRiskEvent.Read.All',
            'IdentityRiskyUser.Read.All',
            'RoleManagement.Read.All',
            'DeviceManagementConfiguration.Read.All',
            'User.Read.All',
            'Group.Read.All',
            'Application.Read.All',
            'AuditLog.Read.All',
            'Device.Read.All'
        )
        
        # Use browser authentication for Graph as well
        Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop
        Write-Host "Connected to Microsoft Graph" -ForegroundColor Green
        
        # Verify Graph connection
        $context = Get-MgContext
        if ($context) {
            Write-Host "Graph Context: $($context.Account) in $($context.TenantId)" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        Write-Host "Graph connection failed. Some assessments may not work." -ForegroundColor Yellow
        Write-Host "Ensure you have admin permissions and the required licenses." -ForegroundColor Gray
        return $false
    }
    
    return $true
}

function Get-DynamicOutputPath {
    param(
        [string]$CustomPath = ""
    )
    
    # If user provided a custom path, use it
    if ($CustomPath -and $CustomPath -ne "") {
        return $CustomPath
    }
    
    # Get current date in a safe filename format
    $dateString = Get-Date -Format "yyyy-MM-dd"
    
    # Get tenant name and sanitize for filename
    $tenantName = if ($Global:TenantName) {
        # Remove invalid filename characters and limit length
        $sanitized = $Global:TenantName -replace '[<>:"/\\|?*]', '-'
        $sanitized = $sanitized -replace '\s+', '-'  # Replace spaces with hyphens
        $sanitized = $sanitized.Substring(0, [Math]::Min($sanitized.Length, 50))  # Limit length
        $sanitized.Trim('-')  # Remove leading/trailing hyphens
    } else {
        "Unknown-Tenant"
    }
    
    # Create filename: TenantName_Azure-Entra-Security-Report_YYYY-MM-DD.html
    $filename = "${tenantName}_Azure-Entra-Security-Report_${dateString}.html"
    
    # Return full path
    return Join-Path (Get-Location) $filename
}

# Export functions for use in other modules
Export-ModuleMember -Function @(
    'Test-RequiredModules',
    'Write-AssessmentResult', 
    'Connect-ToAzureServices',
    'Get-DynamicOutputPath'
) -Variable @(
    'Colors',
    'AssessmentResults', 
    'Essential8Results',
    'RequiredModules',
    'TenantName',
    'TenantId'
) 