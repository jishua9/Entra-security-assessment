# Core Security Assessments Module
# Contains all standard Azure Entra security assessment functions

function Test-SecurityDefaults {
    Write-Host "`n=== Checking Security Defaults ===" -ForegroundColor Cyan
    
    try {
        $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        
        if ($securityDefaults.IsEnabled) {
            Write-AssessmentResult -Category "Security Defaults" -Finding "Security Defaults are enabled" -Severity "Good" -Details "Provides baseline security for the tenant"
        } else {
            Write-AssessmentResult -Category "Security Defaults" -Finding "Security Defaults are disabled" -Severity "Medium" -Recommendation "Consider enabling Security Defaults if not using Conditional Access policies"
        }
    }
    catch {
        Write-AssessmentResult -Category "Security Defaults" -Finding "Unable to retrieve Security Defaults status" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-ConditionalAccessPolicies {
    Write-Host "`n=== Analyzing Conditional Access Policies ===" -ForegroundColor Cyan
    
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy
        
        if ($caPolicies.Count -eq 0) {
            Write-AssessmentResult -Category "Conditional Access" -Finding "No Conditional Access policies found" -Severity "High" -Recommendation "Implement Conditional Access policies for enhanced security"
        } else {
            Write-AssessmentResult -Category "Conditional Access" -Finding "$($caPolicies.Count) Conditional Access policies found" -Severity "Info"
            
            $enabledPolicies = $caPolicies | Where-Object { $_.State -eq 'enabled' }
            $disabledPolicies = $caPolicies | Where-Object { $_.State -eq 'disabled' }
            
            Write-AssessmentResult -Category "Conditional Access" -Finding "$($enabledPolicies.Count) policies enabled, $($disabledPolicies.Count) policies disabled" -Severity "Info"
            
            # Check for MFA enforcement
            $mfaPolicies = $caPolicies | Where-Object { 
                $_.GrantControls.BuiltInControls -contains 'mfa' -and $_.State -eq 'enabled'
            }
            
            if ($mfaPolicies.Count -gt 0) {
                Write-AssessmentResult -Category "Conditional Access" -Finding "$($mfaPolicies.Count) policies enforce MFA" -Severity "Good"
            } else {
                Write-AssessmentResult -Category "Conditional Access" -Finding "No policies found that enforce MFA" -Severity "High" -Recommendation "Create Conditional Access policies that require MFA for users"
            }
            
            # Check for device compliance requirements
            $devicePolicies = $caPolicies | Where-Object { 
                $_.GrantControls.BuiltInControls -contains 'compliantDevice' -and $_.State -eq 'enabled'
            }
            
            if ($devicePolicies.Count -gt 0) {
                Write-AssessmentResult -Category "Conditional Access" -Finding "$($devicePolicies.Count) policies require device compliance" -Severity "Good"
            } else {
                Write-AssessmentResult -Category "Conditional Access" -Finding "No policies require device compliance" -Severity "Medium" -Recommendation "Consider requiring device compliance for accessing corporate resources"
            }
        }
    }
    catch {
        Write-AssessmentResult -Category "Conditional Access" -Finding "Unable to retrieve Conditional Access policies" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-PasswordPolicy {
    Write-Host "`n=== Analyzing Password Policies ===" -ForegroundColor Cyan
    
    try {
        # Check authentication methods policy
        $authMethods = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction SilentlyContinue
        
        if ($authMethods) {
            if ($authMethods.PolicyVersion -eq 'v2') {
                Write-AssessmentResult -Category "Password Policy" -Finding "Authentication methods policy v2 is enabled" -Severity "Good"
            } else {
                Write-AssessmentResult -Category "Password Policy" -Finding "Authentication methods policy v1 is in use" -Severity "Medium" -Recommendation "Consider upgrading to v2 authentication methods policy"
            }
        }
        
        # Check organization password settings
        $org = Get-MgOrganization -ErrorAction SilentlyContinue
        if ($org) {
            Write-AssessmentResult -Category "Password Policy" -Finding "Organization password policies configured" -Severity "Info"
        }
        
        # Check for password protection via domains
        $domains = Get-MgDomain -ErrorAction SilentlyContinue
        if ($domains) {
            $verifiedDomains = $domains | Where-Object { $_.IsVerified -eq $true }
            Write-AssessmentResult -Category "Password Policy" -Finding "$($verifiedDomains.Count) verified domains configured" -Severity "Info"
        }
        
        # Check for on-premises password protection
        try {
            $onPremSync = Get-MgDirectoryOnPremisesSynchronization -ErrorAction SilentlyContinue
            if ($onPremSync) {
                Write-AssessmentResult -Category "Password Policy" -Finding "On-premises synchronization configured" -Severity "Info" -Details "Password policies may be managed on-premises"
            }
        }
        catch {
            # This is expected if no on-premises sync is configured
        }
        
        Write-AssessmentResult -Category "Password Policy" -Finding "Password policy analysis completed" -Severity "Good" -Details "Review authentication methods and organizational policies"
    }
    catch {
        Write-AssessmentResult -Category "Password Policy" -Finding "Unable to fully analyze password policies" -Severity "Low" -Details $_.Exception.Message
    }
}

function Test-PrivilegedRoles {
    Write-Host "`n=== Analyzing Privileged Role Assignments ===" -ForegroundColor Cyan
    
    try {
        # Get directory roles
        $directoryRoles = Get-MgDirectoryRole
        $privilegedRoles = @(
            'Global Administrator',
            'Privileged Role Administrator', 
            'User Administrator',
            'Security Administrator',
            'Conditional Access Administrator',
            'Exchange Administrator',
            'SharePoint Administrator',
            'Application Administrator'
        )
        
        foreach ($role in $directoryRoles) {
            if ($privilegedRoles -contains $role.DisplayName) {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
                
                if ($members.Count -gt 5) {
                    Write-AssessmentResult -Category "Privileged Roles" -Finding "$($role.DisplayName) has $($members.Count) members" -Severity "Medium" -Recommendation "Review and minimize privileged role assignments"
                } elseif ($members.Count -eq 0) {
                    Write-AssessmentResult -Category "Privileged Roles" -Finding "$($role.DisplayName) has no members" -Severity "High" -Recommendation "Ensure at least one break-glass admin account is assigned"
                } else {
                    Write-AssessmentResult -Category "Privileged Roles" -Finding "$($role.DisplayName) has $($members.Count) members" -Severity "Good"
                }
            }
        }
    }
    catch {
        Write-AssessmentResult -Category "Privileged Roles" -Finding "Unable to analyze privileged role assignments" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-GuestUserSettings {
    Write-Host "`n=== Analyzing Guest User Settings ===" -ForegroundColor Cyan
    
    try {
        $org = Get-MgOrganization
        $authorizationPolicy = Get-MgPolicyAuthorizationPolicy
        
        if ($authorizationPolicy.AllowedToCreateApps -eq $false) {
            Write-AssessmentResult -Category "Guest Users" -Finding "Guest users cannot create applications" -Severity "Good"
        } else {
            Write-AssessmentResult -Category "Guest Users" -Finding "Guest users can create applications" -Severity "Medium" -Recommendation "Consider restricting guest users from creating applications"
        }
        
        if ($authorizationPolicy.AllowedToCreateSecurityGroups -eq $false) {
            Write-AssessmentResult -Category "Guest Users" -Finding "Guest users cannot create security groups" -Severity "Good"
        } else {
            Write-AssessmentResult -Category "Guest Users" -Finding "Guest users can create security groups" -Severity "Medium" -Recommendation "Consider restricting guest users from creating security groups"
        }
        
        # Check guest invite settings
        if ($authorizationPolicy.AllowInvitesFrom -eq 'adminsAndGuestInvitors') {
            Write-AssessmentResult -Category "Guest Users" -Finding "Only admins and guest inviters can invite guests" -Severity "Good"
        } elseif ($authorizationPolicy.AllowInvitesFrom -eq 'everyone') {
            Write-AssessmentResult -Category "Guest Users" -Finding "All users can invite guests" -Severity "Medium" -Recommendation "Consider restricting guest invitations to admins only"
        }
    }
    catch {
        Write-AssessmentResult -Category "Guest Users" -Finding "Unable to analyze guest user settings" -Severity "Low" -Details $_.Exception.Message
    }
}

function Test-MFAConfiguration {
    Write-Host "`n=== Analyzing Multi-Factor Authentication ===" -ForegroundColor Cyan
    
    try {
        # Get users and their MFA status
        $users = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,AccountEnabled" | Where-Object { $_.AccountEnabled -eq $true }
        $totalUsers = $users.Count
        $mfaEnabledUsers = 0
        
        # This is a simplified check - in practice, you might want to check authentication methods
        foreach ($user in $users | Select-Object -First 100) { # Limit for performance
            try {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
                if ($authMethods.Count -gt 1) { # More than just password
                    $mfaEnabledUsers++
                }
            }
            catch {
                # User might not have MFA configured
            }
        }
        
        $mfaPercentage = if ($totalUsers -gt 0) { [math]::Round(($mfaEnabledUsers / [math]::Min($totalUsers, 100)) * 100, 2) } else { 0 }
        
        if ($mfaPercentage -ge 90) {
            Write-AssessmentResult -Category "MFA" -Finding "$mfaPercentage% of sampled users have MFA configured" -Severity "Good"
        } elseif ($mfaPercentage -ge 70) {
            Write-AssessmentResult -Category "MFA" -Finding "$mfaPercentage% of sampled users have MFA configured" -Severity "Medium" -Recommendation "Increase MFA adoption across the organization"
        } else {
            Write-AssessmentResult -Category "MFA" -Finding "$mfaPercentage% of sampled users have MFA configured" -Severity "High" -Recommendation "Implement mandatory MFA for all users"
        }
        
        Write-AssessmentResult -Category "MFA" -Finding "Total active users in tenant: $totalUsers" -Severity "Info"
    }
    catch {
        Write-AssessmentResult -Category "MFA" -Finding "Unable to analyze MFA configuration" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-IdentityProtection {
    Write-Host "`n=== Checking Identity Protection ===" -ForegroundColor Cyan
    
    try {
        # Try to check if Identity Protection is available by testing access
        $identityProtectionAvailable = $false
        
        try {
            # Test access to Identity Protection APIs
            $riskyUsers = Get-MgRiskyUser -Top 1 -ErrorAction Stop
            $identityProtectionAvailable = $true
        }
        catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Premium*" -or $_.Exception.Message -like "*license*") {
                Write-AssessmentResult -Category "Identity Protection" -Finding "Identity Protection features not available" -Severity "Medium" -Recommendation "Consider upgrading to Azure AD Premium P2 for Identity Protection features"
                return
            }
        }
        
        if ($identityProtectionAvailable) {
            # Check for risky users using the correct cmdlet
            $riskyUsers = Get-MgRiskyUser -Top 50 -ErrorAction SilentlyContinue
            
            if ($riskyUsers -and $riskyUsers.Count -gt 0) {
                $highRiskUsers = $riskyUsers | Where-Object { $_.RiskLevel -eq 'high' }
                $mediumRiskUsers = $riskyUsers | Where-Object { $_.RiskLevel -eq 'medium' }
                
                if ($highRiskUsers.Count -gt 0) {
                    Write-AssessmentResult -Category "Identity Protection" -Finding "$($highRiskUsers.Count) high-risk users detected" -Severity "High" -Recommendation "Review and remediate high-risk users immediately"
                }
                
                if ($mediumRiskUsers.Count -gt 0) {
                    Write-AssessmentResult -Category "Identity Protection" -Finding "$($mediumRiskUsers.Count) medium-risk users detected" -Severity "Medium" -Recommendation "Review medium-risk users and consider remediation"
                }
                
                Write-AssessmentResult -Category "Identity Protection" -Finding "$($riskyUsers.Count) total risky users found" -Severity "Info" -Details "Identity Protection is monitoring user risk"
            } else {
                Write-AssessmentResult -Category "Identity Protection" -Finding "No risky users detected" -Severity "Good" -Details "Identity Protection is active and monitoring"
            }
            
            # Check for risk detections using the correct cmdlet
            try {
                $riskDetections = Get-MgRiskDetection -Top 10 -ErrorAction SilentlyContinue
                if ($riskDetections -and $riskDetections.Count -gt 0) {
                    Write-AssessmentResult -Category "Identity Protection" -Finding "$($riskDetections.Count) recent risk detections found" -Severity "Info" -Details "Recent risk events detected in the tenant"
                } else {
                    Write-AssessmentResult -Category "Identity Protection" -Finding "No recent risk detections" -Severity "Good"
                }
            }
            catch {
                Write-AssessmentResult -Category "Identity Protection" -Finding "Risk detection data not accessible" -Severity "Info" -Details "May require additional permissions"
            }
        } else {
            Write-AssessmentResult -Category "Identity Protection" -Finding "Identity Protection status unknown" -Severity "Info" -Details "Unable to determine Identity Protection availability"
        }
    }
    catch {
        if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Premium*" -or $_.Exception.Message -like "*license*") {
            Write-AssessmentResult -Category "Identity Protection" -Finding "Identity Protection features not available" -Severity "Medium" -Recommendation "Consider upgrading to Azure AD Premium P2 for Identity Protection features"
        } else {
            Write-AssessmentResult -Category "Identity Protection" -Finding "Unable to check Identity Protection status" -Severity "Low" -Details $_.Exception.Message
        }
    }
}

function Test-ApplicationRegistrations {
    Write-Host "`n=== Analyzing Application Registrations ===" -ForegroundColor Cyan
    
    try {
        $applications = Get-MgApplication -All
        Write-AssessmentResult -Category "Applications" -Finding "$($applications.Count) application registrations found" -Severity "Info"
        
        # Check for applications with expiring secrets/certificates
        $expiringSecrets = @()
        $expiredSecrets = @()
        $expiringCerts = @()
        $expiredCerts = @()
        $orphanedApps = @()
        
        $currentDate = Get-Date
        
        foreach ($app in $applications) {
            # Check owners
            try {
                $owners = Get-MgApplicationOwner -ApplicationId $app.Id -ErrorAction SilentlyContinue
                if ($owners.Count -eq 0) {
                    $orphanedApps += $app
                }
            }
            catch {
                # Assume orphaned if we can't check owners
                $orphanedApps += $app
            }
            
            # Check password credentials (secrets)
            if ($app.PasswordCredentials) {
                foreach ($cred in $app.PasswordCredentials) {
                    if ($cred.EndDateTime) {
                        $daysUntilExpiry = ($cred.EndDateTime - $currentDate).Days
                        if ($daysUntilExpiry -lt 0) {
                            $expiredSecrets += @{ App = $app.DisplayName; DaysOverdue = [Math]::Abs($daysUntilExpiry) }
                        } elseif ($daysUntilExpiry -le 30) {
                            $expiringSecrets += @{ App = $app.DisplayName; DaysLeft = $daysUntilExpiry }
                        }
                    }
                }
            }
            
            # Check key credentials (certificates)
            if ($app.KeyCredentials) {
                foreach ($cred in $app.KeyCredentials) {
                    if ($cred.EndDateTime) {
                        $daysUntilExpiry = ($cred.EndDateTime - $currentDate).Days
                        if ($daysUntilExpiry -lt 0) {
                            $expiredCerts += @{ App = $app.DisplayName; DaysOverdue = [Math]::Abs($daysUntilExpiry) }
                        } elseif ($daysUntilExpiry -le 30) {
                            $expiringCerts += @{ App = $app.DisplayName; DaysLeft = $daysUntilExpiry }
                        }
                    }
                }
            }
        }
        
        # Report findings
        if ($expiredSecrets.Count -gt 0) {
            Write-AssessmentResult -Category "Applications" -Finding "$($expiredSecrets.Count) applications have expired secrets" -Severity "High" -Recommendation "Renew expired application secrets immediately to prevent service disruption"
        }
        
        if ($expiredCerts.Count -gt 0) {
            Write-AssessmentResult -Category "Applications" -Finding "$($expiredCerts.Count) applications have expired certificates" -Severity "High" -Recommendation "Renew expired application certificates immediately"
        }
        
        if ($expiringSecrets.Count -gt 0) {
            Write-AssessmentResult -Category "Applications" -Finding "$($expiringSecrets.Count) applications have secrets expiring within 30 days" -Severity "Medium" -Recommendation "Plan renewal of application secrets before expiration"
        }
        
        if ($expiringCerts.Count -gt 0) {
            Write-AssessmentResult -Category "Applications" -Finding "$($expiringCerts.Count) applications have certificates expiring within 30 days" -Severity "Medium" -Recommendation "Plan renewal of application certificates before expiration"
        }
        
        if ($orphanedApps.Count -gt 0) {
            Write-AssessmentResult -Category "Applications" -Finding "$($orphanedApps.Count) applications have no assigned owners" -Severity "Medium" -Recommendation "Assign owners to applications for proper lifecycle management"
        }
        
        if ($expiredSecrets.Count -eq 0 -and $expiredCerts.Count -eq 0 -and $expiringSecrets.Count -eq 0 -and $expiringCerts.Count -eq 0) {
            Write-AssessmentResult -Category "Applications" -Finding "No application credentials expiring within 30 days" -Severity "Good"
        }
        
    }
    catch {
        Write-AssessmentResult -Category "Applications" -Finding "Unable to analyze application registrations" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-DeviceCompliance {
    Write-Host "`n=== Analyzing Device Compliance ===" -ForegroundColor Cyan
    
    try {
        $devices = Get-MgDevice -All
        Write-AssessmentResult -Category "Devices" -Finding "$($devices.Count) devices registered in the directory" -Severity "Info"
        
        if ($devices.Count -eq 0) {
            Write-AssessmentResult -Category "Devices" -Finding "No devices registered" -Severity "Medium" -Recommendation "Consider implementing device registration for enhanced security"
            return
        }
        
        $currentDate = Get-Date
        $staleDevices = @()
        $enabledDevices = @()
        $managedDevices = @()
        
        foreach ($device in $devices) {
            # Check if device is enabled
            if ($device.AccountEnabled) {
                $enabledDevices += $device
            }
            
            # Check for stale devices (no activity in 90 days)
            if ($device.ApproximateLastSignInDateTime) {
                $daysSinceLastSignIn = ($currentDate - $device.ApproximateLastSignInDateTime).Days
                if ($daysSinceLastSignIn -gt 90) {
                    $staleDevices += $device
                }
            }
            
            # Check if device is managed (has management type)
            if ($device.ManagementType -or $device.IsCompliant) {
                $managedDevices += $device
            }
        }
        
        # Calculate percentages
        $enabledPercentage = if ($devices.Count -gt 0) { [math]::Round(($enabledDevices.Count / $devices.Count) * 100, 2) } else { 0 }
        $managedPercentage = if ($devices.Count -gt 0) { [math]::Round(($managedDevices.Count / $devices.Count) * 100, 2) } else { 0 }
        
        # Report findings
        Write-AssessmentResult -Category "Devices" -Finding "$($enabledDevices.Count) devices are enabled ($enabledPercentage%)" -Severity "Info"
        
        if ($staleDevices.Count -gt 0) {
            $stalePercentage = [math]::Round(($staleDevices.Count / $devices.Count) * 100, 2)
            if ($stalePercentage -gt 20) {
                Write-AssessmentResult -Category "Devices" -Finding "$($staleDevices.Count) devices are stale (>90 days inactive, $stalePercentage%)" -Severity "Medium" -Recommendation "Clean up stale device objects to maintain directory hygiene"
            } else {
                Write-AssessmentResult -Category "Devices" -Finding "$($staleDevices.Count) devices are stale (>90 days inactive, $stalePercentage%)" -Severity "Low" -Recommendation "Consider periodic cleanup of inactive devices"
            }
        } else {
            Write-AssessmentResult -Category "Devices" -Finding "No stale devices detected" -Severity "Good"
        }
        
        if ($managedPercentage -ge 80) {
            Write-AssessmentResult -Category "Devices" -Finding "$($managedDevices.Count) devices are managed ($managedPercentage%)" -Severity "Good"
        } elseif ($managedPercentage -ge 50) {
            Write-AssessmentResult -Category "Devices" -Finding "$($managedDevices.Count) devices are managed ($managedPercentage%)" -Severity "Medium" -Recommendation "Increase device management coverage for better security"
        } else {
            Write-AssessmentResult -Category "Devices" -Finding "$($managedDevices.Count) devices are managed ($managedPercentage%)" -Severity "High" -Recommendation "Implement device management solution to ensure compliance"
        }
        
    }
    catch {
        Write-AssessmentResult -Category "Devices" -Finding "Unable to analyze device compliance" -Severity "Medium" -Details $_.Exception.Message
    }
}

function Test-NamedLocations {
    Write-Host "`n=== Analyzing Named Locations ===" -ForegroundColor Cyan
    
    try {
        $namedLocations = Get-MgIdentityConditionalAccessNamedLocation
        
        if ($namedLocations.Count -eq 0) {
            Write-AssessmentResult -Category "Named Locations" -Finding "No named locations configured" -Severity "Medium" -Recommendation "Configure named locations to enhance Conditional Access policies with location-based controls"
        } else {
            Write-AssessmentResult -Category "Named Locations" -Finding "$($namedLocations.Count) named locations configured" -Severity "Info"
            
            $trustedLocations = $namedLocations | Where-Object { $_.IsTrusted -eq $true }
            $ipBasedLocations = $namedLocations | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.ipNamedLocation' }
            $countryLocations = $namedLocations | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.countryNamedLocation' }
            
            if ($trustedLocations.Count -gt 0) {
                Write-AssessmentResult -Category "Named Locations" -Finding "$($trustedLocations.Count) trusted locations defined" -Severity "Info" -Details "Trusted locations can skip MFA requirements"
            }
            
            if ($ipBasedLocations.Count -gt 0) {
                Write-AssessmentResult -Category "Named Locations" -Finding "$($ipBasedLocations.Count) IP-based locations configured" -Severity "Good"
            }
            
            if ($countryLocations.Count -gt 0) {
                Write-AssessmentResult -Category "Named Locations" -Finding "$($countryLocations.Count) country-based locations configured" -Severity "Good"
            }
            
            # Check if named locations are being used in CA policies
            $caPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue
            $policiesUsingLocations = $caPolicies | Where-Object { 
                $_.Conditions.Locations.IncludeLocations.Count -gt 0 -or $_.Conditions.Locations.ExcludeLocations.Count -gt 0 
            }
            
            if ($policiesUsingLocations.Count -gt 0) {
                Write-AssessmentResult -Category "Named Locations" -Finding "$($policiesUsingLocations.Count) Conditional Access policies use location conditions" -Severity "Good"
            } else {
                Write-AssessmentResult -Category "Named Locations" -Finding "Named locations exist but are not used in Conditional Access policies" -Severity "Medium" -Recommendation "Leverage named locations in Conditional Access policies for location-based security"
            }
        }
        
    }
    catch {
        Write-AssessmentResult -Category "Named Locations" -Finding "Unable to analyze named locations" -Severity "Low" -Details $_.Exception.Message
    }
}

function Test-SignInLogs {
    Write-Host "`n=== Analyzing Sign-in Patterns (Last 7 Days) ===" -ForegroundColor Cyan
    
    try {
        # Get sign-ins from last 7 days
        $startDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $signIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $startDate" -Top 1000
        
        if ($signIns.Count -eq 0) {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "No sign-in logs available for analysis" -Severity "Low" -Details "May require Azure AD Premium license or recent activity"
            return
        }
        
        Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$($signIns.Count) sign-in events analyzed (last 7 days)" -Severity "Info"
        
        # Analyze failed sign-ins
        $failedSignIns = $signIns | Where-Object { $_.Status.ErrorCode -ne 0 }
        $failedPercentage = if ($signIns.Count -gt 0) { [math]::Round(($failedSignIns.Count / $signIns.Count) * 100, 2) } else { 0 }
        
        if ($failedPercentage -gt 20) {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$($failedSignIns.Count) failed sign-ins ($failedPercentage%)" -Severity "High" -Recommendation "Investigate high failure rate - possible attack or configuration issues"
        } elseif ($failedPercentage -gt 10) {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$($failedSignIns.Count) failed sign-ins ($failedPercentage%)" -Severity "Medium" -Recommendation "Monitor failed sign-in patterns for potential security issues"
        } else {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$($failedSignIns.Count) failed sign-ins ($failedPercentage%)" -Severity "Good"
        }
        
        # Check for legacy authentication
        $legacyAuth = $signIns | Where-Object { 
            $_.ClientAppUsed -in @('Exchange ActiveSync', 'Other clients', 'IMAP', 'MAPI', 'POP', 'SMTP') -or
            $_.ClientAppUsed -like '*Legacy*'
        }
        
        if ($legacyAuth.Count -gt 0) {
            $legacyPercentage = [math]::Round(($legacyAuth.Count / $signIns.Count) * 100, 2)
            if ($legacyPercentage -gt 5) {
                Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$($legacyAuth.Count) legacy authentication attempts ($legacyPercentage%)" -Severity "High" -Recommendation "Block legacy authentication protocols - they bypass MFA and modern security controls"
            } else {
                Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$($legacyAuth.Count) legacy authentication attempts ($legacyPercentage%)" -Severity "Medium" -Recommendation "Consider blocking remaining legacy authentication usage"
            }
        } else {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "No legacy authentication detected" -Severity "Good"
        }
        
        # Check for impossible travel (basic analysis)
        $uniqueUsers = $signIns | Group-Object -Property UserId
        $suspiciousTravel = 0
        
        foreach ($userGroup in $uniqueUsers) {
            $userSignIns = $userGroup.Group | Sort-Object CreatedDateTime
            for ($i = 1; $i -lt $userSignIns.Count; $i++) {
                $prevSignIn = $userSignIns[$i-1]
                $currentSignIn = $userSignIns[$i]
                
                if ($prevSignIn.Location.CountryOrRegion -and $currentSignIn.Location.CountryOrRegion) {
                    if ($prevSignIn.Location.CountryOrRegion -ne $currentSignIn.Location.CountryOrRegion) {
                        $timeDiff = $currentSignIn.CreatedDateTime - $prevSignIn.CreatedDateTime
                        if ($timeDiff.TotalHours -lt 2) {
                            $suspiciousTravel++
                        }
                    }
                }
            }
        }
        
        if ($suspiciousTravel -gt 0) {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "$suspiciousTravel potential impossible travel events detected" -Severity "Medium" -Recommendation "Review sign-ins with rapid geographic changes - may indicate compromised accounts"
        }
        
        # Check geographic distribution
        $countries = $signIns | Where-Object { $_.Location.CountryOrRegion } | Group-Object -Property { $_.Location.CountryOrRegion } | Sort-Object Count -Descending
        if ($countries.Count -gt 10) {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "Sign-ins from $($countries.Count) different countries" -Severity "Medium" -Recommendation "Monitor geographic sign-in patterns for unusual activity"
        } elseif ($countries.Count -gt 0) {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "Sign-ins from $($countries.Count) countries" -Severity "Info" -Details "Top countries: $($countries[0..2].Name -join ', ')"
        }
        
    }
    catch {
        if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Premium*") {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "Sign-in logs not accessible" -Severity "Low" -Recommendation "Azure AD Premium license may be required for detailed sign-in analytics"
        } else {
            Write-AssessmentResult -Category "Sign-in Analysis" -Finding "Unable to analyze sign-in logs" -Severity "Low" -Details $_.Exception.Message
        }
    }
}

# Export all core assessment functions
Export-ModuleMember -Function @(
    'Test-SecurityDefaults',
    'Test-ConditionalAccessPolicies',
    'Test-PasswordPolicy',
    'Test-PrivilegedRoles',
    'Test-GuestUserSettings',
    'Test-MFAConfiguration',
    'Test-IdentityProtection',
    'Test-ApplicationRegistrations',
    'Test-DeviceCompliance',
    'Test-NamedLocations',
    'Test-SignInLogs'
) 