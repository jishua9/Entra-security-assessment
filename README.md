# Azure Entra Security Assessment Tool

A comprehensive PowerShell-based security assessment tool for Azure Entra (formerly Azure AD) tenants. This tool analyzes various security settings, policies, and configurations to provide a detailed interactive health report with **smart recommendations** and **score-based impact analysis**.

## ✨ Key Features

### **🎯 Interactive Top Priority Actions**
- **Dynamic recommendations** based on your specific findings
- **Score impact calculation** (+4, +8, +12 points per fix)
- **Expandable detailed guidance** with step-by-step instructions
- **PowerShell commands** ready to copy and execute
- **Click-to-expand** interface for comprehensive remediation steps

### **📊 Smart Security Scoring**
- **Realistic scoring algorithm** (20-100 scale)
- **Weighted impact assessment** (Critical: -12, High: -8, Medium: -4, Low: -2 points)
- **Good practice bonuses** (+3 points each, max +20)
- **Real-world adjustments** to prevent artificially low scores

### **📁 Automatic File Naming**
- **Tenant-specific filenames**: `CompanyName_Azure-Entra-Security-Report_2025-01-15.html`
- **Date integration** for chronological organization
- **Safe filename sanitization** for all environments

### **🔧 Professional Interactive Reports**
- **Expandable sections** for detailed findings
- **Export capabilities** (PDF, CSV, Print)
- **Modern responsive design** with dark theme
- **Interactive charts** showing security posture

## 🔍 What It Analyzes

The tool performs comprehensive security assessments across multiple areas using Microsoft Graph API and Azure PowerShell:

### **Security Policies & Controls**

#### **1. Security Defaults** 
- **Endpoint:** `GET /policies/identitySecurityDefaultsEnforcementPolicy`
- **PowerShell:** `Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy`
- **Checks:** 
  - Whether Security Defaults are enabled or disabled
  - Impact on baseline security posture
  - Compatibility with Conditional Access policies

#### **2. Conditional Access Policies**
- **Endpoint:** `GET /identity/conditionalAccess/policies`
- **PowerShell:** `Get-MgIdentityConditionalAccessPolicy`
- **Checks:**
  - Total number of Conditional Access policies
  - Enabled vs disabled policy count
  - MFA enforcement through grant controls (`mfa` requirement)
  - Device compliance requirements (`compliantDevice` control)
  - Policy coverage and gaps

#### **3. Password Policies**
- **Endpoints:** 
  - `GET /domains` 
  - `GET /organization`
  - `GET /policies/authenticationMethodsPolicy`
- **PowerShell:** `Get-MgDomain`, `Get-MgOrganization`, `Get-MgPolicyAuthenticationMethodPolicy`
- **Checks:**
  - Authentication methods policy version (v1 vs v2)
  - Password validation policies
  - On-premises password protection configuration

#### **4. Identity Protection**
- **Endpoints:**
  - `GET /identityProtection/riskyUsers`
  - `GET /identityProtection/riskDetections`
- **PowerShell:** `Get-MgRiskyUser`, `Get-MgRiskDetection`
- **Checks:**
  - High-risk users requiring immediate attention
  - Recent risk detections and events
  - Risk-based policy effectiveness
  - **Requires:** Azure AD Premium P2 license

### **Access Management**

#### **5. Privileged Role Assignments**
- **Endpoints:**
  - `GET /directoryRoles`
  - `GET /directoryRoles/{id}/members`
- **PowerShell:** `Get-MgDirectoryRole`, `Get-MgDirectoryRoleMember`
- **Analyzes Roles:**
  - Global Administrator
  - Privileged Role Administrator
  - User Administrator
  - Security Administrator
  - Conditional Access Administrator
  - Exchange Administrator
  - SharePoint Administrator
  - Application Administrator
- **Checks:**
  - Member count per privileged role
  - Over-privileged accounts (>5 members)
  - Under-privileged roles (0 members - break-glass concern)

#### **6. Guest User Settings**
- **Endpoints:**
  - `GET /organization`
  - `GET /policies/authorizationPolicy`
- **PowerShell:** `Get-MgOrganization`, `Get-MgPolicyAuthorizationPolicy`
- **Checks:**
  - Guest user application creation permissions (`allowedToCreateApps`)
  - Guest user security group creation (`allowedToCreateSecurityGroups`)
  - Guest invitation restrictions (`allowInvitesFrom`)
  - External collaboration settings

#### **7. Multi-Factor Authentication**
- **Endpoints:**
  - `GET /users`
  - `GET /users/{id}/authentication/methods`
- **PowerShell:** `Get-MgUser`, `Get-MgUserAuthenticationMethod`
- **Checks:**
  - MFA adoption rate across active users
  - Authentication method diversity (beyond password)
  - Sampling methodology for large tenants (100 user sample)
  - Total active user count

#### **8. Application Registrations**
- **Endpoints:**
  - `GET /applications`
  - `GET /applications/{id}/owners`
- **PowerShell:** `Get-MgApplication`, `Get-MgApplicationOwner`
- **Checks:**
  - Expired client secrets and certificates
  - Applications without assigned owners
  - Credential expiration monitoring (30-day window)
  - Service continuity risks

#### **9. Device Management**
- **Endpoints:**
  - `GET /devices`
- **PowerShell:** `Get-MgDevice`
- **Checks:**
  - Device registration status
  - Stale devices (>90 days inactive)
  - Device compliance and management
  - Directory hygiene

#### **10. Named Locations**
- **Endpoints:**
  - `GET /identity/conditionalAccess/namedLocations`
- **PowerShell:** `Get-MgIdentityConditionalAccessNamedLocation`
- **Checks:**
  - Configured trusted locations
  - IP-based vs country-based locations
  - Integration with Conditional Access policies
  - Location-based security controls

#### **11. Sign-in Analysis**
- **Endpoints:**
  - `GET /auditLogs/signIns`
- **PowerShell:** `Get-MgAuditLogSignIn`
- **Checks:**
  - Failed sign-in patterns (last 7 days)
  - Legacy authentication usage
  - Geographic sign-in distribution
  - Impossible travel detection
  - **Requires:** Azure AD Premium license for detailed logs

### **Compliance & Governance**

#### **12. Tenant Configuration**
- **Endpoints:**
  - `GET /organization`
  - `GET /domains`
- **PowerShell:** `Get-MgOrganization`, `Get-MgDomain`
- **Checks:**
  - Tenant-wide security settings
  - Domain validation and configuration
  - Directory synchronization status

## 🛡️ Essential 8 Security Framework Integration

The tool now includes comprehensive **Essential 8** compliance assessments alongside standard Azure Entra security checks. The Essential 8 is an Australian Cyber Security Centre (ACSC) framework focusing on 8 key mitigation strategies.

### **Essential 8 Categories Assessed**

#### **1. Application Control** 
- **Checks:**
  - Application consent policies configuration
  - Intune application protection policies
  - Enterprise app creation restrictions
  - Mobile application management (MAM) policies
- **Cloud Context:** Controls which applications can be installed and run on managed devices

#### **2. Patch Applications**
- **Checks:**
  - Microsoft 365 Apps update policies
  - Intune application update configurations
  - Microsoft Store for Business app management
  - Device configuration policies for app updates
- **Cloud Context:** Ensures applications are kept up-to-date with security patches

#### **3. Configure Microsoft Office Macro Settings**
- **Checks:**
  - Office configuration policies via Intune
  - Administrative templates for Office security
  - Group Policy configurations through Intune
  - Microsoft 365 Security & Compliance policies
- **Cloud Context:** Controls macro execution and Office security settings

#### **4. User Application Hardening**
- **Checks:**
  - Browser security policies (Edge, Chrome)
  - Endpoint protection configurations
  - Application protection policies
  - Security baseline compliance
- **Cloud Context:** Hardens user-facing applications against attacks

#### **5. Restrict Administrative Privileges**
- **Enhanced Checks:**
  - Privileged Identity Management (PIM) configuration
  - Administrative workstation policies
  - Conditional Access policies for admin roles
  - Just-in-time access controls
- **Cloud Context:** Builds on standard privilege analysis with Essential 8 focus

#### **6. Patch Operating Systems**
- **Checks:**
  - Windows Update for Business policies
  - Device compliance policies for OS versions
  - Update ring configurations
  - OS security baseline compliance
- **Cloud Context:** Ensures operating systems receive timely security updates

#### **7. Multi-Factor Authentication**
- **Enhanced Analysis:**
  - References standard MFA assessment
  - Passwordless authentication methods
  - Advanced MFA capabilities (FIDO2, Windows Hello)
  - Authentication strength policies
- **Cloud Context:** Builds on existing comprehensive MFA analysis

#### **8. Regular Backups**
- **Checks:**
  - Azure Backup policies
  - Microsoft 365 data protection policies
  - OneDrive backup configurations
  - Device backup policies
  - Data retention settings
- **Cloud Context:** Ensures data protection and recovery capabilities

### **Essential 8 Compliance Scoring**

The tool provides a dedicated **Essential 8 compliance score** alongside the main security score:

- **Compliant Categories**: Fully meeting Essential 8 requirements
- **Partially Compliant**: Some controls in place but improvements needed  
- **Non-Compliant**: Essential 8 requirements not met

**Compliance Levels:**
- **75%+ Compliance**: Excellent Essential 8 posture
- **50-74% Compliance**: Good foundation with some gaps
- **<50% Compliance**: Significant Essential 8 improvements needed

### **Essential 8 Reporting Features**

- **Separate Essential 8 section** in console output with dedicated scoring
- **Category breakdown** showing compliance status per Essential 8 area
- **Integrated recommendations** linking Essential 8 gaps to remediation steps
- **HTML report integration** with Essential 8 findings alongside standard security checks

### **License and Permission Requirements for Essential 8**

Many Essential 8 checks require additional Microsoft licensing:

| Essential 8 Category | Required Licenses | API Permissions |
|---------------------|-------------------|-----------------|
| Application Control | Intune, Azure AD Premium | `DeviceManagementApps.Read.All` |
| Patch Applications | Intune | `DeviceManagementConfiguration.Read.All` |
| Office Macro Settings | Intune, Microsoft 365 | `DeviceManagementConfiguration.Read.All` |
| User App Hardening | Intune, Defender for Endpoint | `DeviceManagementConfiguration.Read.All` |
| Restrict Admin Privileges | Azure AD Premium P2 (PIM) | `RoleManagement.Read.All` |
| Patch Operating Systems | Intune | `DeviceManagementConfiguration.Read.All` |
| Multi-Factor Authentication | Azure AD Premium | `Policy.Read.All` |
| Regular Backups | Azure Backup, Microsoft 365 | `InformationProtectionPolicy.Read.All` |

**Note:** The tool gracefully handles missing licenses and will indicate which features require additional licensing.

## 🚀 Quick Start

### **1. Setup Requirements**
First, run the setup script to install required PowerShell modules:

```powershell
# Run as Administrator (recommended) or Current User
.\setup-requirements.ps1
```

### **2. Run Security Assessment**
Execute the main assessment script:

```powershell
# Basic assessment with automatic file naming
.\Azure-Entra-Security-Assessment.ps1

# Custom output path (overrides automatic naming)
.\Azure-Entra-Security-Assessment.ps1 -OutputPath "C:\Reports\MyCustomReport.html"

# Detailed console output
.\Azure-Entra-Security-Assessment.ps1 -DetailedOutput
```

### **3. Interactive Authentication**
The tool uses **device authentication** for secure, interactive login:
- No app registration required
- Uses your existing Azure credentials
- Supports MFA and conditional access policies
- Minimal permissions requested (read-only access)

### **4. Automatic File Naming**
Reports are automatically named with tenant and date:
```
Contoso-Ltd_Azure-Entra-Security-Report_2025-01-15.html
Microsoft-Corporation_Azure-Entra-Security-Report_2025-01-15.html
```

## 📊 Interactive Report Features

### **🎯 Top Priority Actions**
- **Smart recommendations** based on your specific security findings
- **Score impact display** showing exact points gained per action
- **Expandable details** with comprehensive remediation guidance
- **Step-by-step instructions** for each recommendation
- **Ready-to-use PowerShell commands** for implementation

### **📈 Security Score Dashboard**
- **Realistic scoring** from 20-100 (prevents artificially low scores)
- **Visual score representation** with interactive doughnut chart
- **Detailed breakdown** of score calculation methodology
- **Risk level assessment** (Excellent, Good, Fair, Needs Improvement, Poor, Critical)

### **🎨 Modern Interactive Interface**
- **Dark theme** professional design
- **Expandable finding tables** (auto-expand for Critical/High severity)
- **Interactive charts** powered by Chart.js
- **Export functionality** (PDF, CSV, Print)
- **Responsive design** for desktop and mobile viewing

### **Color-Coded Severity Levels**
- 🔴 **Critical** - Immediate action required (-12 points each)
- 🟣 **High** - High priority security concerns (-8 points each)
- 🟡 **Medium** - Recommended improvements (-4 points each)
- 🔵 **Low** - Minor optimizations (-2 points each)
- 🟢 **Good** - Security best practices followed (+3 points each, max +20)

### **📋 Key Security Insights**
- **Active Users** count
- **Applications** registered
- **Registered Devices** count
- **Conditional Access Policies** deployed

## 🎯 Top Priority Actions Examples

The tool generates dynamic recommendations based on your findings. Here are examples of what you might see:

### **🔐 Authentication & Access Control**
- **Implement mandatory MFA for all users** (+8 points)
- **Enable Security Defaults or expand CA policies** (+4 points)  
- **Block legacy authentication protocols** (+8 points)

### **👥 Privileged Access Management**
- **Assign break-glass admin to Exchange Administrator role** (+8 points)
- **Review 6 Global Administrator assignments** (+4 points)

### **🏢 Guest User Security**
- **Restrict guest user permissions** (+4 points)
- **Restrict guest invitations to admins only** (+4 points)

### **📱 Application & Device Management**
- **Assign owners to orphaned applications** (+4 points)
- **Renew expired application credentials** (+12 points)
- **Implement device registration and management** (+4 points)

### **📊 Monitoring & Analysis**
- **Investigate failed sign-in patterns** (+4 points)
- **Review and remediate risky user accounts** (+8 points)

**Each recommendation includes:**
- **Why This Matters** - Security impact explanation
- **How to Fix** - Step-by-step Azure Portal instructions
- **PowerShell Commands** - Ready-to-execute code snippets

## 🔧 Prerequisites

### **PowerShell Modules**
The tool automatically installs these modules if missing:
- `Az.Accounts` - Azure authentication
- `Az.Resources` - Azure resource management
- `Microsoft.Graph.Authentication` - Graph API authentication
- `Microsoft.Graph.Identity.SignIns` - Sign-in and Conditional Access data
- `Microsoft.Graph.Identity.DirectoryManagement` - Directory and policy data
- `Microsoft.Graph.Users` - User and authentication data
- `Microsoft.Graph.Groups` - Group management data
- `Microsoft.Graph.DeviceManagement` - Device compliance data
- `Microsoft.Graph.Applications` - Application registration data
- `Microsoft.Graph.Reports` - Audit and sign-in logs

### **Permissions Required**
The tool requests these **read-only** permissions:

| Permission | Usage | Assessment Areas |
|------------|--------|------------------|
| `Directory.Read.All` | Read directory objects, users, groups | User enumeration, directory roles, organization settings |
| `Policy.Read.All` | Read authentication and authorization policies | Conditional Access, Security Defaults, Authorization policies |
| `UserAuthenticationMethod.Read.All` | Read user MFA methods | MFA adoption analysis, authentication method diversity |
| `IdentityRiskEvent.Read.All` | Read identity protection risk events | Risk detection, risky user identification |
| `IdentityRiskyUser.Read.All` | Read risky user data | High-risk user assessment |
| `RoleManagement.Read.All` | Read role assignments and definitions | Privileged role membership analysis |
| `DeviceManagementConfiguration.Read.All` | Read device management policies | Device compliance requirements |
| `User.Read.All` | Read user profiles | Active user enumeration, account status |
| `Group.Read.All` | Read group information | Group membership and management settings |
| `Application.Read.All` | Read application registrations | App credential expiration, ownership |
| `AuditLog.Read.All` | Read audit logs and sign-ins | Sign-in pattern analysis, legacy auth detection |
| `Device.Read.All` | Read device information | Device registration and compliance status |

### **Admin Consent Required**
Most permissions require **admin consent** as they access tenant-wide security data. The tool uses application permissions (not delegated) for comprehensive assessment.

### **License Requirements**
- **Basic features**: Available with any Azure AD license
- **Identity Protection**: Requires Azure AD Premium P2
- **Conditional Access**: Requires Azure AD Premium P1/P2
- **Detailed Sign-in Logs**: Requires Azure AD Premium P1/P2

## 🛠️ Advanced Usage

### **Automatic File Naming (Default)**
```powershell
.\Azure-Entra-Security-Assessment.ps1
# Generates: Contoso-Ltd_Azure-Entra-Security-Report_2025-01-15.html
```

### **Custom Report Location**
```powershell
.\Azure-Entra-Security-Assessment.ps1 -OutputPath "C:\Reports\CustomName.html"
```

### **Detailed Console Output**
```powershell
.\Azure-Entra-Security-Assessment.ps1 -DetailedOutput
```

### **Scheduled Assessments**
Create a scheduled task for regular security assessments:

```powershell
# Example: Weekly security assessment with automatic naming
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File 'C:\Scripts\Azure-Entra-Security-Assessment.ps1'"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6AM
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Weekly Azure Security Assessment"
```

## 📊 Understanding the Security Score

### **Scoring Methodology**
- **Base Score**: 100 points
- **Critical Issues**: -12 points each
- **High Priority**: -8 points each  
- **Medium Priority**: -4 points each
- **Low Priority**: -2 points each
- **Good Practices**: +3 points each (maximum +20 bonus)
- **Minimum Score**: 20 (real-world adjustments applied)

### **Risk Level Thresholds**
- **85-100**: Excellent - Industry leading practices
- **70-84**: Good - Strong security posture with minor gaps
- **55-69**: Fair - Solid foundation with some improvements needed
- **40-54**: Needs Improvement - Basic security with important gaps
- **25-39**: Poor - Significant vulnerabilities require attention
- **20-24**: Critical - Major security vulnerabilities need immediate action

### **Real-World Adjustments**
- Environments with minimal findings get minimum 60 points
- No critical issues + ≤2 high issues = minimum 50 points
- Prevents artificially low scores that don't reflect actual risk

## 🔍 Interactive Report Navigation

### **📊 Summary Dashboard**
- **Security Score** with visual gauge and explanation
- **Findings Summary** with color-coded counts
- **Top Priority Actions** with expandable detailed guidance
- **Key Security Insights** showing tenant metrics

### **📋 Detailed Findings Tables**
- **Auto-expand** Critical and High severity findings
- **Click to expand** any severity level for full details
- **Structured data** with Title, Severity, Warning, and Recommendations
- **Search and filter** capabilities

### **🎯 Interactive Recommendations**
- **Click any recommendation** to expand detailed guidance
- **"Why This Matters"** - Security impact explanation
- **"How to Fix"** - Step-by-step remediation instructions
- **PowerShell commands** - Copy-ready code snippets
- **Score impact** - Exact points gained per action

### **📤 Export Options**
- **PDF Export** - Print-friendly report generation
- **CSV Export** - Data analysis and tracking
- **Print Report** - Professional document printing

## 🚨 Troubleshooting

### **Common Issues**

**Module Installation Fails**
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
Install-Module -Name Az -Force -AllowClobber
Install-Module -Name Microsoft.Graph -Force -AllowClobber
```

**Authentication Issues**
- Ensure you have appropriate Azure AD permissions
- Check if conditional access policies block the connection
- Verify network connectivity to Azure services
- Use an account with at least Security Reader role

**Graph API Errors**
- Some features require Azure AD Premium licenses
- Check if the requesting account has sufficient permissions
- Verify tenant settings allow the requested operations
- Review the detailed error messages in console output

**File Naming Issues**
- Tool automatically sanitizes tenant names for safe filenames
- Invalid characters are replaced with hyphens
- Length is limited to 50 characters for compatibility
- Falls back to "Unknown-Tenant" if tenant name unavailable

### **Corporate Network Considerations**
```powershell
# Configure proxy if needed
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
```

## 📋 Best Practices

### **Regular Assessments**
- Run monthly security assessments
- Compare results over time using date-stamped reports
- Track improvement progress with score changes
- Document remediation efforts and timelines

### **Stakeholder Reporting**
- Share interactive HTML reports with security teams
- Use Top Priority Actions for executive summaries
- Include in compliance documentation
- Export CSV data for trend analysis

### **Remediation Priorities**
1. **Critical Issues** - Address immediately (highest point impact)
2. **High Priority** - Plan within 30 days
3. **Medium Priority** - Schedule within 90 days
4. **Low Priority** - Include in next maintenance cycle
5. **Monitor Good Practices** - Maintain current standards

### **Leveraging Interactive Features**
- **Click through all recommendations** for comprehensive understanding
- **Use PowerShell commands** provided in expanded sections
- **Export reports** for offline analysis and archival
- **Share specific findings** by expanding relevant sections

## 🔐 Security & Privacy

- **Read-only access** - No modifications made to your tenant
- **Interactive authentication** - Uses your credentials securely
- **Local processing** - Assessment runs on your machine
- **No data transmission** - Results stay in your environment
- **Automatic file naming** - Includes tenant name for organization

## 📈 Continuous Improvement

This tool is designed to evolve with Azure Entra security features. Regular updates include:
- **New security assessment checks** for emerging threats
- **Enhanced interactive reporting** capabilities
- **Improved scoring algorithms** based on real-world feedback
- **Additional PowerShell automation** for remediation
- **Extended analytics** and trend analysis features

## 🤝 Support

For issues, questions, or feature requests:
- Review the troubleshooting section above
- Check Azure documentation for specific policy guidance
- Consult Microsoft security baselines and best practices
- Engage with Azure security community forums

---

**⚠️ Important Note**: This tool provides security assessments and recommendations but should be used alongside comprehensive security planning and professional security advice. Always test changes in a non-production environment first. The interactive recommendations include PowerShell commands - review and test these carefully before execution in production environments. 