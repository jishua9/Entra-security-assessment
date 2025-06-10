# Azure Entra Security Assessment Tool

A comprehensive PowerShell-based security assessment tool for Azure Entra (formerly Azure AD) tenants. This tool analyzes various security settings, policies, and configurations to provide a detailed health report on your organization's identity and access management security posture.

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
- **PowerShell:** `Get-MgIdentityProtectionRiskyUser`, `Get-MgIdentityProtectionRiskDetection`
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

### **Compliance & Governance**

#### **8. Tenant Configuration**
- **Endpoints:**
  - `GET /organization`
  - `GET /domains`
- **PowerShell:** `Get-MgOrganization`, `Get-MgDomain`
- **Checks:**
  - Tenant-wide security settings
  - Domain validation and configuration
  - Directory synchronization status

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
# Basic assessment with HTML report
.\Azure-Entra-Security-Assessment.ps1

# Detailed output with custom report location
.\Azure-Entra-Security-Assessment.ps1 -OutputPath ".\MyTenant-Security-Report.html" -DetailedOutput
```

### **3. Interactive Authentication**
The tool uses **device authentication** for secure, interactive login:
- No app registration required
- Uses your existing Azure credentials
- Supports MFA and conditional access policies
- Minimal permissions requested (read-only access)

## 📊 Report Features

### **Color-Coded Severity Levels**
- 🔴 **Critical** - Immediate action required
- 🟣 **High** - High priority security concerns  
- 🟡 **Medium** - Recommended improvements
- 🔵 **Low** - Minor optimizations
- 🟢 **Good** - Security best practices followed

### **Comprehensive HTML Report**
- Executive summary with issue counts
- Detailed findings with recommendations
- Actionable remediation steps
- Professional formatting for stakeholder review

### **Console Output**
- Real-time progress updates
- Color-coded findings during execution
- Summary statistics at completion

## 🎯 Security Assessment Criteria

### **Critical Issues** 🔴
- **No privileged role members** - Risk of tenant lockout
- **No break-glass accounts** - Recovery access concerns

### **High Priority Issues** 🟣
- **No Conditional Access policies** - Missing modern authentication controls
- **No MFA enforcement policies** - Weak authentication security
- **0% MFA adoption** - Users without multi-factor authentication
- **High-risk users unaddressed** - Active security threats

### **Medium Priority Issues** 🟡
- **Security Defaults disabled** - Without compensating Conditional Access
- **Excessive privileged accounts** - More than 5 members in admin roles
- **Permissive guest settings** - Guests can create apps/groups
- **Mixed authentication policy versions** - Using legacy v1 policies

### **Low Priority Issues** 🔵
- **Missing policy optimization** - Opportunities for improvement
- **Limited feature access** - Premium license features unavailable

### **Good Practices** 🟢
- **MFA adoption >90%** - Strong authentication coverage
- **Conditional Access implemented** - Modern access controls
- **Appropriate role assignments** - Well-managed privileged access
- **Security Defaults enabled** - Or compensating Conditional Access
- **Guest access controlled** - Restricted external collaboration

## 🔧 Prerequisites

### **PowerShell Modules**
The tool automatically installs these modules if missing:
- `Az.Accounts` - Azure authentication
- `Az.Resources` - Azure resource management
- `Microsoft.Graph.*` - Graph API access for identity data

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

### **Admin Consent Required**
Most permissions require **admin consent** as they access tenant-wide security data. The tool uses application permissions (not delegated) for comprehensive assessment.

### **License Requirements**
- **Basic features**: Available with any Azure AD license
- **Identity Protection**: Requires Azure AD Premium P2
- **Conditional Access**: Requires Azure AD Premium P1/P2

## 🎯 Security Assessment Areas

### **1. Authentication Security**
- Multi-factor authentication adoption
- Authentication method policies
- Password protection settings
- Security defaults configuration

### **2. Access Control**
- Conditional access policy coverage
- Device compliance requirements
- Location-based access controls
- Application access policies

### **3. Identity Governance**
- Privileged role management
- Guest user access controls
- Group management policies
- Application permissions

### **4. Threat Protection**
- Identity protection configuration
- Risk-based policies
- Suspicious activity detection
- Automated remediation

## 🛠️ Advanced Usage

### **Custom Report Location**
```powershell
.\Azure-Entra-Security-Assessment.ps1 -OutputPath "C:\Reports\Security-Assessment-$(Get-Date -Format 'yyyy-MM-dd').html"
```

### **Detailed Console Output**
```powershell
.\Azure-Entra-Security-Assessment.ps1 -DetailedOutput
```

### **Scheduled Assessments**
Create a scheduled task for regular security assessments:

```powershell
# Example: Weekly security assessment
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File 'C:\Scripts\Azure-Entra-Security-Assessment.ps1'"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6AM
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Weekly Azure Security Assessment"
```

## 🔍 Understanding Results

### **Critical Issues** 🔴
- No MFA enforcement
- Overprivileged accounts
- Disabled security features
- High-risk users unaddressed

### **High Priority** 🟣
- Weak conditional access coverage
- Excessive guest permissions
- Missing device compliance
- Unmonitored privileged roles

### **Medium Priority** 🟡
- Suboptimal policy configuration
- Limited security monitoring
- Governance improvements needed

### **Good Practices** 🟢
- Proper MFA implementation
- Well-configured conditional access
- Appropriate role assignments
- Active threat monitoring

## 🚨 Troubleshooting

### **Common Issues**

**Module Installation Fails**
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
Install-Module -Name Az -Force -AllowClobber
```

**Authentication Issues**
- Ensure you have appropriate Azure AD permissions
- Check if conditional access policies block the connection
- Verify network connectivity to Azure services

**Graph API Errors**
- Some features require Azure AD Premium licenses
- Check if the requesting account has sufficient permissions
- Verify tenant settings allow the requested operations

### **Corporate Network Considerations**
```powershell
# Configure proxy if needed
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
```

## 📋 Best Practices

### **Regular Assessments**
- Run monthly security assessments
- Compare results over time
- Track improvement progress
- Document remediation efforts

### **Stakeholder Reporting**
- Share HTML reports with security teams
- Include in compliance documentation
- Use for security awareness training
- Support audit requirements

### **Remediation Priorities**
1. Address critical issues immediately
2. Plan high-priority improvements
3. Schedule medium-priority enhancements
4. Monitor and maintain good practices

## 🔐 Security & Privacy

- **Read-only access** - No modifications made to your tenant
- **Interactive authentication** - Uses your credentials securely
- **Local processing** - Assessment runs on your machine
- **No data transmission** - Results stay in your environment

## 📈 Continuous Improvement

This tool is designed to evolve with Azure Entra security features. Regular updates will include:
- New security assessment checks
- Enhanced reporting capabilities
- Support for additional policies
- Improved recommendations

## 🤝 Support

For issues, questions, or feature requests:
- Review the troubleshooting section
- Check Azure documentation for specific policy guidance
- Consult Microsoft security baselines
- Engage with Azure security community

---

**⚠️ Important Note**: This tool provides security assessments and recommendations but should be used alongside comprehensive security planning and professional security advice. Always test changes in a non-production environment first. 