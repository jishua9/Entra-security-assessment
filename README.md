# Azure Entra Security Assessment Tool

A comprehensive PowerShell-based security assessment tool for Azure Entra (formerly Azure AD) tenants. This tool analyzes various security settings, policies, and configurations to provide a detailed health report on your organization's identity and access management security posture.

## 🔍 What It Analyzes

The tool performs comprehensive security assessments across multiple areas:

### **Security Policies & Controls**
- **Security Defaults** - Baseline security enablement status
- **Conditional Access Policies** - MFA enforcement, device compliance, policy coverage
- **Password Policies** - Authentication method policies and password protection
- **Identity Protection** - Risk users, risk events, and threat detection

### **Access Management**
- **Privileged Role Assignments** - Admin role membership and distribution
- **Guest User Settings** - External collaboration security controls
- **Multi-Factor Authentication** - MFA adoption rates and configuration

### **Compliance & Governance**
- **Device Management** - Compliance policy enforcement
- **Application Permissions** - App registration security
- **Directory Settings** - Tenant-wide security configurations

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

## 🔧 Prerequisites

### **PowerShell Modules**
The tool automatically installs these modules if missing:
- `Az.Accounts` - Azure authentication
- `Az.Resources` - Azure resource management
- `Microsoft.Graph.*` - Graph API access for identity data

### **Permissions Required**
The tool requests these **read-only** permissions:
- `Directory.Read.All` - Read directory data
- `Policy.Read.All` - Read policies and conditional access
- `UserAuthenticationMethod.Read.All` - Read MFA settings
- `IdentityRiskEvent.Read.All` - Read identity protection data
- `RoleManagement.Read.All` - Read role assignments

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