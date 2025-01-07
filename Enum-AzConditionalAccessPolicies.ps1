# Ensure the Microsoft Graph module is installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.ConditionalAccess)) {
    Install-Module -Name Microsoft.Graph -Scope CurrentUser
}

# Import Microsoft Graph module
Import-Module Microsoft.Graph.Identity.ConditionalAccess

# Display banner
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "       Azure Conditional Access Policy     " -ForegroundColor Yellow
Write-Host "         Analysis and Enumeration Tool     " -ForegroundColor Yellow
Write-Host "          Author: Liam Romanis (2024)      " -ForegroundColor Yellow
Write-Host "===========================================" -ForegroundColor Cyan
 
# Authenticate with Microsoft Graph
Write-Host "Authenticating with Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "Policy.Read.All", "Directory.Read.All", "Group.Read.All", "Application.Read.All"

# Function to fetch all users in the tenant
function Get-TotalUsers {
    Write-Host "Fetching all users in the tenant..." -ForegroundColor Cyan
    $users = Get-MgUser -All
    Write-Host "Total users retrieved: $($users.Count)" -ForegroundColor Green
    return $users.Count
}

# Function to resolve group names
function Get-GroupNames {
    param (
        [string[]]$GroupIds
    )
    Write-Host "Resolving group names..." -ForegroundColor Cyan
    $groupNames = @()
    foreach ($groupId in $GroupIds) {
        try {
            $group = Get-MgGroup -GroupId $groupId
            $groupNames += $group.DisplayName
        } catch {
            Write-Host "Error resolving group: $groupId. $_" -ForegroundColor Red
            $groupNames += "Unknown Group ($groupId)"
        }
    }
    return $groupNames -join ", "
}

# Function to resolve resource names
function Get-ResourceNames {
    param (
        [string[]]$ResourceIds
    )
    Write-Host "Resolving resource names..." -ForegroundColor Cyan
    $resourceNames = @()
    foreach ($resourceId in $ResourceIds) {
        if ($resourceId -eq "All") {
            return "All"
        }
        try {
            $resource = Get-MgApplication -ApplicationId $resourceId
            $resourceNames += $resource.DisplayName
        } catch {
            Write-Host "Error resolving resource: $resourceId. $_" -ForegroundColor Red
            $resourceNames += "Unknown Resource ($resourceId)"
        }
    }
    return $resourceNames -join ", "
}

# Function to resolve unique users from users, groups, and roles
function Get-UniqueUsers {
    param (
        [string[]]$Users,
        [string[]]$Groups,
        [string[]]$Roles
    )
    Write-Host "Resolving unique users from users, groups, and roles..." -ForegroundColor Cyan
    $allUsers = @()

    # Add direct users
    $allUsers += $Users

    # Resolve group members
    foreach ($groupId in $Groups) {
        try {
            $groupMembers = Get-MgGroupMember -GroupId $groupId -All
            $allUsers += $groupMembers.Id
        } catch {
            Write-Host "Error resolving members for group $groupId. $_" -ForegroundColor Red
        }
    }

    # Resolve role members
    foreach ($roleId in $Roles) {
        try {
            $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "RoleDefinitionId eq '$roleId'"
            $allUsers += $roleAssignments.PrincipalId
        } catch {
            Write-Host "Error resolving members for role $roleId. $_" -ForegroundColor Red
        }
    }

    # Return unique users
    $uniqueUsers = $allUsers | Sort-Object -Unique
    Write-Host "Unique users resolved: $($uniqueUsers.Count)" -ForegroundColor Green
    return $uniqueUsers
}

# Fetch total users
$totalUsers = Get-TotalUsers

# Fetch conditional access policies
Write-Host "Fetching conditional access policies..." -ForegroundColor Cyan
$policies = Get-MgIdentityConditionalAccessPolicy
if ($policies) {
    Write-Host "Total conditional access policies retrieved: $($policies.Count)" -ForegroundColor Green
} else {
    Write-Host "No conditional access policies found." -ForegroundColor Yellow
    $policies = @()
}

# Prepare CSV output
$output = @()

# Process each policy
Write-Host "Processing conditional access policies..." -ForegroundColor Cyan
foreach ($policy in $policies) {
    $name = $policy.DisplayName
    Write-Host "Processing policy: $name" -ForegroundColor Yellow

    $conditions = $policy.Conditions
    $usersCondition = $conditions.Users

    # Included entities
    $includedUsers = $usersCondition.IncludeUsers
    $includedGroups = $usersCondition.IncludeGroups
    $includedRoles = $usersCondition.IncludeRoles

    # Excluded entities
    $excludedUsers = $usersCondition.ExcludeUsers
    $excludedGroups = $usersCondition.ExcludeGroups
    $excludedRoles = $usersCondition.ExcludeRoles

    # Calculate total included users
    if ($includedUsers -contains "All") {
        $totalIncludedUsers = $totalUsers
    } else {
        $totalIncludedUsers = (Get-UniqueUsers -Users $includedUsers -Groups $includedGroups -Roles $includedRoles).Count
    }

    # Calculate total excluded users
    $totalExcludedUsers = (Get-UniqueUsers -Users $excludedUsers -Groups $excludedGroups -Roles $excludedRoles).Count

    # Calculate unaffected users
    $unaffectedUsers = $totalUsers - $totalIncludedUsers

    # Resolve group names
    $includedGroupNames = Get-GroupNames -GroupIds $includedGroups
    $excludedGroupNames = Get-GroupNames -GroupIds $excludedGroups

    # Resolve resource names
    $includedResourceNames = Get-ResourceNames -ResourceIds $conditions.Applications.IncludeApplications
    $excludedResourceNames = Get-ResourceNames -ResourceIds $conditions.Applications.ExcludeApplications

    # Build row for CSV
    $output += [PSCustomObject]@{
        "CA Name"             = $name
        "Total Included Users" = $totalIncludedUsers
        "Total Excluded Users" = $totalExcludedUsers
        "Users Unaffected"     = $unaffectedUsers
        "Included Roles"       = ($includedRoles -join ", ")
        "Excluded Roles"       = ($excludedRoles -join ", ")
        "Included Group Names" = $includedGroupNames
        "Excluded Group Names" = $excludedGroupNames
        "Included Resource Names" = $includedResourceNames
        "Excluded Resource Names" = $excludedResourceNames
    }
}

# Export to CSV
Write-Host "Exporting data to CSV..." -ForegroundColor Cyan
$output | Export-Csv -Path "ConditionalAccessPolicies.csv" -NoTypeInformation -Force
Write-Host "Analysis complete. Output saved to 'ConditionalAccessPolicies.csv'." -ForegroundColor Green
