# Report Generation Module
# Contains scoring, recommendations, and HTML report generation functions

function Calculate-RiskScore {
    Write-Host "📊 Calculating security risk score..." -ForegroundColor Cyan
    
    # Count findings by severity
    $criticalCount = $Global:AssessmentResults.Critical.Count
    $highCount = $Global:AssessmentResults.High.Count
    $mediumCount = $Global:AssessmentResults.Medium.Count
    $lowCount = $Global:AssessmentResults.Low.Count
    $goodCount = $Global:AssessmentResults.Good.Count
    
    $totalFindings = $criticalCount + $highCount + $mediumCount + $lowCount
    
    Write-Host "  Critical Issues: $criticalCount" -ForegroundColor Red
    Write-Host "  High Priority: $highCount" -ForegroundColor Magenta
    Write-Host "  Medium Priority: $mediumCount" -ForegroundColor Yellow
    Write-Host "  Low Priority: $lowCount" -ForegroundColor Cyan
    Write-Host "  Good Practices: $goodCount" -ForegroundColor Green
    
    # Start with base score of 100
    $baseScore = 100
    
    # More realistic weighted deductions based on security impact
    # Critical issues are severe security risks but shouldn't destroy the score
    $criticalDeduction = $criticalCount * 12
    # High issues are significant risks
    $highDeduction = $highCount * 8
    # Medium issues are moderate risks
    $mediumDeduction = $mediumCount * 4
    # Low issues are minor improvements
    $lowDeduction = $lowCount * 2
    
    $totalDeductions = $criticalDeduction + $highDeduction + $mediumDeduction + $lowDeduction
    
    # Calculate base score after deductions (minimum 20 to avoid extremely low scores)
    $score = [Math]::Max(20, $baseScore - $totalDeductions)
    
    # Add significant bonus points for good practices (up to 20 points)
    $goodBonus = [Math]::Min(20, $goodCount * 3)
    $score = [Math]::Min(100, $score + $goodBonus)
    
    # Apply a "real-world adjustment" - most organizations should score 40+ if they have basic security
    if ($totalFindings -le 10 -and $criticalCount -eq 0) {
        $score = [Math]::Max($score, 60)  # Minimum 60 for low-finding environments
    }
    if ($criticalCount -eq 0 -and $highCount -le 2) {
        $score = [Math]::Max($score, 50)  # Minimum 50 for environments without critical issues
    }
    
    # Determine risk level with more realistic thresholds
    $level = if ($score -ge 85) { "EXCELLENT" }
            elseif ($score -ge 70) { "GOOD" }
            elseif ($score -ge 55) { "FAIR" }
            elseif ($score -ge 40) { "NEEDS IMPROVEMENT" }
            elseif ($score -ge 25) { "POOR" }
            else { "CRITICAL" }
    
    # Provide context
    $context = switch ($level) {
        "EXCELLENT" { "Outstanding security posture - industry leading practices" }
        "GOOD" { "Strong security posture with room for optimization" }
        "FAIR" { "Solid security foundation with some gaps to address" }
        "NEEDS IMPROVEMENT" { "Basic security in place but important improvements needed" }
        "POOR" { "Significant security gaps require attention" }
        "CRITICAL" { "Major security vulnerabilities need immediate action" }
    }
    
    Write-Host "  Security Score: $score/100 ($level)" -ForegroundColor $(
        switch ($level) {
            "EXCELLENT" { "Green" }
            "GOOD" { "Green" }
            "FAIR" { "Yellow" }
            "NEEDS IMPROVEMENT" { "Yellow" }
            "POOR" { "Magenta" }
            "CRITICAL" { "Red" }
        }
    )
    Write-Host "  Assessment: $context" -ForegroundColor Gray
    
    return @{ 
        Score = $score
        Level = $level
        Context = $context
        Breakdown = @{
            Critical = $criticalCount
            High = $highCount
            Medium = $mediumCount
            Low = $lowCount
            Good = $goodCount
            CriticalDeduction = $criticalDeduction
            HighDeduction = $highDeduction
            MediumDeduction = $mediumDeduction
            LowDeduction = $lowDeduction
            GoodBonus = $goodBonus
        }
    }
}

function Generate-KeyInsights {
    $insights = @()
    $totalUsers = ($Global:AssessmentResults.Info | Where-Object { $_.Category -eq "MFA" -and $_.Finding -like "*Total active users*" }).Finding
    $totalApps = ($Global:AssessmentResults.Info | Where-Object { $_.Category -eq "Applications" -and $_.Finding -like "*application registrations found*" }).Finding
    $totalDevices = ($Global:AssessmentResults.Info | Where-Object { $_.Category -eq "Devices" -and $_.Finding -like "*devices registered*" }).Finding
    $totalPolicies = ($Global:AssessmentResults.Info | Where-Object { $_.Category -eq "Conditional Access" -and $_.Finding -like "*Conditional Access policies found*" }).Finding
    
    if ($totalUsers) {
        $userCount = ($totalUsers -split ': ')[1]
        $insights += "<div class='insight-card'><div class='insight-number'>$userCount</div><div class='insight-label'>Active Users</div></div>"
    }
    
    if ($totalApps) {
        $appCount = ($totalApps -split ' ')[0]
        $insights += "<div class='insight-card'><div class='insight-number'>$appCount</div><div class='insight-label'>Applications</div></div>"
    }
    
    if ($totalDevices) {
        $deviceCount = ($totalDevices -split ' ')[0]
        $insights += "<div class='insight-card'><div class='insight-number'>$deviceCount</div><div class='insight-label'>Registered Devices</div></div>"
    }
    
    if ($totalPolicies) {
        $policyCount = ($totalPolicies -split ' ')[0]
        $insights += "<div class='insight-card'><div class='insight-number'>$policyCount</div><div class='insight-label'>CA Policies</div></div>"
    }
    
    return $insights -join "`n"
}

function Generate-TopRecommendations {
    Write-Host "Generating top priority recommendations..." -ForegroundColor Yellow
    
    # Define potential score impacts for different finding types
    $scoreImpacts = @{
        'Critical' = 12
        'High' = 8
        'Medium' = 4
        'Low' = 2
    }
    
    # Collect all actionable findings with their potential impact
    $actionableFindings = @()
    
    foreach ($severity in @('Critical', 'High', 'Medium', 'Low')) {
        foreach ($finding in $Global:AssessmentResults[$severity]) {
            $impact = $scoreImpacts[$severity]
            $shortRecommendation = Get-ShortRecommendation -Finding $finding
            
            if ($shortRecommendation) {
                $actionableFindings += @{
                    Severity = $severity
                    Finding = $finding
                    Impact = $impact
                    ShortRecommendation = $shortRecommendation
                    Priority = Get-FindingPriority -Finding $finding -Severity $severity
                }
            }
        }
    }
    
    # Sort by priority (highest impact first, then by severity)
    $topFindings = $actionableFindings | Sort-Object Priority, { $scoreImpacts[$_.Severity] } -Descending | Select-Object -First 5
    
    # Generate HTML for top recommendations with detailed content
    $recommendationsHtml = @()
    foreach ($item in $topFindings) {
        $severityClass = $item.Severity.ToLower()
        $severityLabel = switch ($item.Severity) {
            'Critical' { 'CRIT' }
            'High' { 'HIGH' }
            'Medium' { 'MED' }
            'Low' { 'LOW' }
        }
        
        $detailedInfo = Get-DetailedRecommendation -Finding $item.Finding
        
        $recommendationsHtml += @"
                        <div class="recommendation-item">
                            <div class="rec-priority $severityClass">$severityLabel</div>
                            <div class="rec-text">
                                $($item.ShortRecommendation)
                                <span class="rec-expand-icon">▶</span>
                                <div class="score-impact">+$($item.Impact) points</div>
                                <div class="rec-details">
                                    $detailedInfo
                                </div>
                            </div>
                        </div>
"@
    }
    
    if ($recommendationsHtml.Count -eq 0) {
        return '<div class="recommendation-item"><div class="rec-priority good" style="background-color: #059669;">GOOD</div><div class="rec-text">No critical improvements identified<div class="score-impact">Maintain current practices</div></div></div>'
    }
    
    return $recommendationsHtml -join "`n"
}

function Get-ShortRecommendation {
    param($Finding)
    
    # Extract actionable short recommendations based on finding patterns
    switch -Wildcard ($Finding.Finding) {
        "*MFA*configured*" {
            if ($Finding.Finding -like "*2.94%*" -or $Finding.Finding -match '\d+\.\d+%.*MFA') {
                return "Implement mandatory MFA for all users (currently low adoption)"
            }
        }
        "*Security Defaults are disabled*" {
            return "Enable Security Defaults or expand Conditional Access policies"
        }
        "*Exchange Administrator has no members*" {
            return "Assign break-glass admin to Exchange Administrator role"
        }
        "*Global Administrator has*members*" {
            if ($Finding.Finding -match '(\d+) members') {
                $count = $matches[1]
                if ([int]$count -gt 5) {
                    return "Review $count Global Administrator assignments"
                }
            }
        }
        "*Guest users can create*" {
            return "Restrict guest user permissions"
        }
        "*All users can invite guests*" {
            return "Restrict guest invitations to admins only"
        }
        "*applications have no assigned owners*" {
            return "Assign owners to orphaned applications"
        }
        "*expired*" {
            return "Renew expired application credentials"
        }
        "*No devices registered*" {
            return "Implement device registration and management"
        }
        "*failed sign-ins*" {
            if ($Finding.Finding -match '(\d+\.\d+)%') {
                return "Investigate failed sign-in patterns ($($matches[1])%)"
            }
        }
        "*legacy authentication*" {
            return "Block legacy authentication protocols"
        }
        "*risky users*" {
            return "Review and remediate risky user accounts"
        }
        default {
            # Return null for non-actionable findings
            return $null
        }
    }
    
    return $null
}

function Get-FindingPriority {
    param($Finding, $Severity)
    
    # Assign priority scores (higher = more important)
    $basePriority = switch ($Severity) {
        'Critical' { 1000 }
        'High' { 500 }
        'Medium' { 100 }
        'Low' { 50 }
    }
    
    # Boost priority for high-impact security findings
    $priorityBoost = 0
    switch -Wildcard ($Finding.Finding) {
        "*MFA*" { $priorityBoost += 200 }  # MFA is critical
        "*Exchange Administrator has no members*" { $priorityBoost += 150 }  # Break-glass access
        "*Security Defaults*" { $priorityBoost += 100 }  # Basic security
        "*expired*" { $priorityBoost += 175 }  # Service disruption risk
        "*Global Administrator*" { $priorityBoost += 125 }  # Privileged access
        "*legacy authentication*" { $priorityBoost += 150 }  # Security bypass
        "*risky users*" { $priorityBoost += 180 }  # Active threats
        default { $priorityBoost += 0 }
    }
    
    return $basePriority + $priorityBoost
}

function Get-DetailedRecommendation {
    param($Finding)
    
    # Generate detailed recommendations with step-by-step instructions
    $details = switch -Wildcard ($Finding.Finding) {
        "*MFA*configured*" {
            @"
<h5>Why This Matters</h5>
<p>Multi-Factor Authentication (MFA) is your strongest defense against credential-based attacks. Even if passwords are compromised, MFA prevents unauthorized access.</p>
<h5>How to Fix</h5>
<p>1. Navigate to Azure Portal > Azure Active Directory > Security > Conditional Access</p>
<p>2. Create a new policy requiring MFA for all users</p>
<p>3. Test with pilot group first, then roll out organization-wide</p>
<code>New-MgIdentityConditionalAccessPolicy -DisplayName "Require MFA for All Users"</code>
"@
        }
        "*Security Defaults are disabled*" {
            @"
<h5>Why This Matters</h5>
<p>Security Defaults provide baseline security for tenants without Conditional Access policies. They enforce MFA and block legacy authentication.</p>
<h5>How to Fix</h5>
<p>1. If you have Conditional Access policies, ensure they cover MFA requirements</p>
<p>2. Otherwise, enable Security Defaults in Azure Portal > Azure Active Directory > Properties</p>
<code>Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled `$true</code>
"@
        }
        "*Exchange Administrator has no members*" {
            @"
<h5>Why This Matters</h5>
<p>Break-glass admin accounts ensure you can maintain access to critical services during emergencies or when primary admins are unavailable.</p>
<h5>How to Fix</h5>
<p>1. Create a dedicated break-glass account (e.g., breakglass@domain.com)</p>
<p>2. Assign it to Exchange Administrator role</p>
<p>3. Store credentials securely and document emergency procedures</p>
<code>New-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "DisplayName eq 'Exchange Administrator'").Id -Id (Get-MgUser -Filter "DisplayName eq 'BreakGlass'").Id</code>
"@
        }
        "*Global Administrator has*members*" {
            @"
<h5>Why This Matters</h5>
<p>Too many Global Administrators increases your attack surface. Each additional GA represents a potential security risk if compromised.</p>
<h5>How to Fix</h5>
<p>1. Review current Global Administrator assignments</p>
<p>2. Assign users to least-privilege roles instead (User Admin, Security Admin, etc.)</p>
<p>3. Keep only 2-4 Global Administrators for break-glass scenarios</p>
<code>Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").Id</code>
"@
        }
        "*Guest users can create*" {
            @"
<h5>Why This Matters</h5>
<p>Guest users with excessive permissions can create security risks and compliance issues in your tenant.</p>
<h5>How to Fix</h5>
<p>1. Navigate to Azure Portal > Azure Active Directory > External Identities > External collaboration settings</p>
<p>2. Restrict guest user permissions to "Guest users have limited access to properties and memberships"</p>
<p>3. Review and update guest user access policies</p>
<code>Update-MgPolicyAuthorizationPolicy -AllowedToCreateApps `$false -AllowedToCreateSecurityGroups `$false</code>
"@
        }
        "*applications have no assigned owners*" {
            @"
<h5>Why This Matters</h5>
<p>Orphaned applications create security risks and compliance issues. Without owners, these apps may have excessive permissions or expired credentials.</p>
<h5>How to Fix</h5>
<p>1. Review all application registrations in Azure Portal > App registrations</p>
<p>2. Assign owners to each application</p>
<p>3. Review and clean up unused applications</p>
<code>Get-MgApplication | Where-Object { (Get-MgApplicationOwner -ApplicationId `$_.Id).Count -eq 0 }</code>
"@
        }
        "*expired*" {
            @"
<h5>Why This Matters</h5>
<p>Expired application credentials can cause service disruptions and security vulnerabilities. Applications may fail to authenticate properly.</p>
<h5>How to Fix</h5>
<p>1. Identify applications with expired credentials</p>
<p>2. Generate new client secrets or certificates</p>
<p>3. Update application configurations with new credentials</p>
<code>Get-MgApplication | Where-Object { `$_.PasswordCredentials.EndDateTime -lt (Get-Date) }</code>
"@
        }
        "*legacy authentication*" {
            @"
<h5>Why This Matters</h5>
<p>Legacy authentication protocols bypass modern security controls like MFA, making them a major security risk.</p>
<h5>How to Fix</h5>
<p>1. Create a Conditional Access policy to block legacy authentication</p>
<p>2. Target "Exchange ActiveSync clients" and "Other clients"</p>
<p>3. Monitor sign-in logs to ensure no disruption to legitimate services</p>
<code># Create CA policy to block legacy authentication via Azure Portal</code>
"@
        }
        "*failed sign-ins*" {
            @"
<h5>Why This Matters</h5>
<p>High failure rates may indicate brute force attacks, misconfigured applications, or user experience issues that need attention.</p>
<h5>How to Fix</h5>
<p>1. Analyze sign-in logs to identify failure patterns</p>
<p>2. Look for repeated failures from same IPs or users</p>
<p>3. Implement account lockout policies if needed</p>
<code>Get-MgAuditLogSignIn -Filter "status/errorCode ne 0" -Top 100</code>
"@
        }
        default {
            @"
<h5>Additional Information</h5>
<p>Review the detailed findings in the tables below for specific remediation steps.</p>
<h5>General Best Practices</h5>
<p>• Regularly review security settings and policies</p>
<p>• Implement least-privilege access principles</p>
<p>• Monitor audit logs for suspicious activity</p>
"@
        }
    }
    
    return $details
}

function Generate-RemediationActions {
    param($Finding)
    
    $actions = @()
    
    # Add specific PowerShell commands based on finding type
    switch -Wildcard ($Finding.Finding) {
        "*Security Defaults are disabled*" {
            $actions += "# Enable Security Defaults`nUpdate-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled `$true"
        }
        "*No Conditional Access policies*" {
            $actions += "# Create a basic MFA policy via Azure Portal`n# Navigate to: Azure AD > Security > Conditional Access > New Policy"
        }
        "*expired secrets*" {
            $actions += "# Find applications with expired secrets`nGet-MgApplication | Where-Object { `$_.PasswordCredentials.EndDateTime -lt (Get-Date) }"
        }
        "*stale devices*" {
            $actions += "# Remove stale devices (>90 days inactive)`nGet-MgDevice | Where-Object { `$_.ApproximateLastSignInDateTime -lt (Get-Date).AddDays(-90) } | Remove-MgDevice"
        }
        "*legacy authentication*" {
            $actions += "# Block legacy authentication via Conditional Access`n# Create CA policy targeting legacy authentication protocols"
        }
    }
    
    return $actions -join "`n"
}

function Generate-HtmlReport {
    param([string]$OutputPath)
    
    Write-Host "`n=== Generating Enhanced HTML Report ===" -ForegroundColor Cyan
    
    # Check if template exists
    $templatePath = ".\report-template.html"
    if (!(Test-Path $templatePath)) {
        Write-Warning "Template file not found at $templatePath. Using basic template."
        Generate-BasicHtmlReport -OutputPath $OutputPath
        return
    }
    
    # Read template
    $template = Get-Content $templatePath -Raw
    
    # Calculate risk score
    $riskData = Calculate-RiskScore
    
    # Generate insights
    $insights = Generate-KeyInsights
    
    # Generate top recommendations
    $topRecommendations = Generate-TopRecommendations
    
    # Generate Essential 8 content
    $essential8Content = Generate-Essential8Content
    $essential8Score = Calculate-Essential8Score
    
    # Generate findings content as tables (excluding Essential 8 findings)
    $findingsContent = ""
    
    foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Good', 'Info')) {
        # Filter out Essential 8 findings for the standard findings section
        $standardFindings = $Global:AssessmentResults[$severity] | Where-Object { $_.Category -notlike "*Essential 8*" }
        
        if ($standardFindings.Count -gt 0) {
            $displayName = switch ($severity) {
                'Critical' { 'Critical Priority' }
                'High' { 'High Priority' }
                'Medium' { 'Medium Priority' }
                'Low' { 'Low Priority' }
                'Good' { 'Good Practices' }
                'Info' { 'Information' }
            }
            
            $tableId = "table-$($severity.ToLower())"
            $findingsContent += @"
            <div class="findings-table">
                <div class="table-header">
                    <div class="table-title">$displayName Findings</div>
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span class="findings-count">$($Global:AssessmentResults[$severity].Count)</span>
                        <button class="expand-toggle" onclick="toggleTable('$tableId')" data-table="$tableId" data-severity="$severity">
                            <span class="expand-icon">▶</span>
                        </button>
                    </div>
                </div>
                <div class="table-content" id="$tableId">
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 25%;">Title</th>
                                <th style="width: 10%;">Severity</th>
                                <th style="width: 35%;">Warning</th>
                                <th style="width: 30%;">Recommendations</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            
            foreach ($finding in $Global:AssessmentResults[$severity]) {
                $severityColor = switch ($severity) {
                    'Critical' { '#dc2626' }
                    'High' { '#ea580c' }
                    'Medium' { '#d97706' }
                    'Low' { '#2563eb' }
                    'Good' { '#059669' }
                    'Info' { '#6b7280' }
                }
                
                $warningText = "$($finding.Category): $($finding.Finding)"
                if ($finding.Details) {
                    $warningText += " " + $finding.Details
                }
                
                $recommendationText = ""
                if ($finding.Recommendation) {
                    $recommendationText += "<strong>Recommendation:</strong> " + $finding.Recommendation
                }
                
                $remediationActions = Generate-RemediationActions -Finding $finding
                if ($remediationActions) {
                    if ($recommendationText) { $recommendationText += "<br><br>" }
                    $recommendationText += "<strong>Remediation:</strong> " + $remediationActions
                }
                
                $findingsContent += @"
                            <tr>
                                <td>
                                    <div class="finding-title">$($finding.Category)</div>
                                </td>
                                <td>
                                    <span class="severity-badge $($severity.ToLower())" style="background-color: $severityColor;">$severity</span>
                                </td>
                                <td>
                                    <div class="finding-description">$warningText</div>
                                </td>
                                <td>
                                    <div class="recommendation-text">$recommendationText</div>
                                </td>
                            </tr>
"@
            }
            
            $findingsContent += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
        }
    }
    
    # Replace template placeholders
    $tenantDisplayName = if ($Global:TenantName) { $Global:TenantName } else { "Unknown Tenant" }
    $html = $template -replace '{{TIMESTAMP}}', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $html = $html -replace '{{TENANT_NAME}}', $tenantDisplayName
    $html = $html -replace '{{RISK_SCORE}}', $riskData.Score
    $html = $html -replace '{{RISK_LEVEL}}', $riskData.Level
    $html = $html -replace '{{CRITICAL_COUNT}}', $Global:AssessmentResults.Critical.Count
    $html = $html -replace '{{HIGH_COUNT}}', $Global:AssessmentResults.High.Count
    $html = $html -replace '{{MEDIUM_COUNT}}', $Global:AssessmentResults.Medium.Count
    $html = $html -replace '{{LOW_COUNT}}', $Global:AssessmentResults.Low.Count
    $html = $html -replace '{{GOOD_COUNT}}', $Global:AssessmentResults.Good.Count
    $html = $html -replace '{{INSIGHTS_CONTENT}}', $insights
    $html = $html -replace '{{TOP_RECOMMENDATIONS}}', $topRecommendations
    $html = $html -replace '{{FINDINGS_CONTENT}}', $findingsContent
    
    # Write to file
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Enhanced HTML report generated: $OutputPath" -ForegroundColor Green
    Write-Host "Features: Interactive charts, risk scoring, remediation actions, export options" -ForegroundColor Gray
}

function Generate-BasicHtmlReport {
    param([string]$OutputPath)
    
    # Fallback basic HTML if template is missing
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Entra Security Assessment Report</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        .finding { margin: 15px 0; padding: 15px; border-radius: 5px; border-left: 4px solid; }
        .critical { background-color: #f77468; border-color: #e74c3c; }
        .high { background-color: #f8a0a0; border-color: #e91e63; }
        .medium { background-color: #ebd481; border-color: #f39c12; }
        .low { background-color: #b8e0ff; border-color: #3498db; }
        .good { background-color: #7bdda5; border-color: #27ae60; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure Entra Security Assessment Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
"@

    foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Good', 'Info')) {
        if ($Global:AssessmentResults[$severity].Count -gt 0) {
            $html += "<h2>$severity Priority Findings ($($Global:AssessmentResults[$severity].Count))</h2>"
            foreach ($finding in $Global:AssessmentResults[$severity]) {
                $html += "<div class='finding $($severity.ToLower())'><strong>$($finding.Category):</strong> $($finding.Finding)</div>"
            }
        }
    }

    $html += "</div></body></html>"
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

function Show-Summary {
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "AZURE ENTRA SECURITY ASSESSMENT SUMMARY" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    $totalFindings = $Global:AssessmentResults.Critical.Count + $Global:AssessmentResults.High.Count + $Global:AssessmentResults.Medium.Count + $Global:AssessmentResults.Low.Count
    
    Write-Host "`nFindings Summary:" -ForegroundColor White
    Write-Host "  Critical Issues: $($Global:AssessmentResults.Critical.Count)" -ForegroundColor Red
    Write-Host "  High Priority:   $($Global:AssessmentResults.High.Count)" -ForegroundColor Magenta
    Write-Host "  Medium Priority: $($Global:AssessmentResults.Medium.Count)" -ForegroundColor Yellow
    Write-Host "  Low Priority:    $($Global:AssessmentResults.Low.Count)" -ForegroundColor Cyan
    Write-Host "  Good Practices:  $($Global:AssessmentResults.Good.Count)" -ForegroundColor Green
    Write-Host "  Total Issues:    $totalFindings" -ForegroundColor White
    
    if ($Global:AssessmentResults.Critical.Count -gt 0) {
        Write-Host "`nIMMEDIATE ACTION REQUIRED - Critical security issues found!" -ForegroundColor Red
    } elseif ($Global:AssessmentResults.High.Count -gt 0) {
        Write-Host "`nHigh priority security issues require attention" -ForegroundColor Magenta
    } elseif ($totalFindings -eq 0) {
        Write-Host "`nNo security issues identified in this assessment" -ForegroundColor Green
    } else {
        Write-Host "`nNo critical issues found, but some improvements recommended" -ForegroundColor Green
    }
    
    # Essential 8 compliance section will be added by main script
}

# Export all reporting functions
Export-ModuleMember -Function @(
    'Calculate-RiskScore',
    'Generate-KeyInsights',
    'Generate-TopRecommendations', 
    'Get-ShortRecommendation',
    'Get-FindingPriority',
    'Get-DetailedRecommendation',
    'Generate-RemediationActions',
    'Generate-HtmlReport',
    'Generate-BasicHtmlReport',
    'Show-Summary'
) 
