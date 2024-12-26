<#
    .SYNOPSIS
        This script is intended to help customers migrate their Azure and Arc Onboarded Non-Azure machines and respective files, services tracking and registry settings onboarded to the legacy Change Tracking & Inventory using MMA agent to the latest Change Tracking & Inventory solution using AMA agent.
        This script will not migrate file content changes and custom alerts configured. Please refer to https://learn.microsoft.com/en-us/azure/automation/change-tracking/guidance-migration-log-analytics-monitoring-agent?tabs=ct-single-vm%2Climit-single-vm for more guidance on the same.
        This script will not migrate Non-Azure Machines which are not onboarded to Arc.
        This script is designed to migrate at a log analytics workspace level.

    .DESCRIPTION
        This script will do the following.
        1. Get list of all Azure and Arc Onboarded Non-Azure machines onboarded to Input Log Analytics Workspace for Change Tracking solution using MMA Agent.
        2. Create the Data Collection Rule (DCR) ARM template by fetching the files, services, tracking & registry settings configured in the legacy solution and translating them to equivalent settings for the latest solution using AMA Agent and Change Tracking Extensions for the Output Log Analytics Workspace.
        3. Deploy Change Tracking solution ARM template to Output Log Analytics Workspace. This is done only if migration to same workspace is not done. The output workspace requires the legacy solution to create the log analytics tables for Change Tracking like ConfigurationChange & ConfigurationData. The deployment name will be DeployCTSolution_CTMig_{GUID} and it will be in same resource group as Output Log Analytics Workspace.
        4. Deploy the DCR ARM template created in Step 2. The deployment name will be OutputDCRName_CTMig_{GUID} and it will be in same resource group as Output Log Analytics Workspace. The DCR will be created in the same location as the Output Log Analytics Workspace.
        5. Removes MMA Agent from machines list populated in Step 1. This is done only if migration to same workspace is carried out. Machines which have the MMA agent installed via the MSI, will not have the MMA agent removed. It will be removed only if the MMA Agent was installed as an extension.
        6. Assign DCR to machines and install AMA Agent and CT Extensions. The deployment name witll be MachineName_CTMig and it will be in same resource group as the machine.
            6.1 Assign the DCR deployed in Step 4 to all machines populated in Step 1.
            6.2 Install the AMA Agent to all machines populated in Step 1.
            6.3 Install the CT Agent to all machines populated in Step 1.

    .PARAMETER InputLogAnalyticsWorkspaceResourceId
        Mandatory
        Log Analytics Workspace where legacy Change Tracking solution is being used.

    .PARAMETER OutputLogAnalyticsWorkspaceResourceId
        Mandatory
        Log Analytics Workspace where latest Change Tracking solution using AMA Agent is to be configured.
    
    .PARAMETER OutputDCRName
        Mandatory
        The Data Collection Rule name for latest Change Tracking solution.
                
    .PARAMETER OutputVerbose
        Mandatory
        Put true if verbose output is required. Default is false.

    .PARAMETER AzureEnvironment
        Mandatory
        Azure Cloud Environment to which Log Analytics Workspace belongs.
        Accepted values are AzureCloud, AzureUSGovernment, AzureChinaCloud.
                
    .EXAMPLE
        CTMigration -InputLogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"  -OutputLogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}" -OutputDCRName "DCRMig" -OutputVerbose $false -AzureEnvironment "AzureCloud"

    .OUTPUTS
        Outputs the status of each steps of the migration.
#>
param (
	
    [Parameter(Mandatory = $True)]
    [String]$InputLogAnalyticsWorkspaceResourceId,
    [Parameter(Mandatory = $True)]
    [String]$OutputLogAnalyticsWorkspaceResourceId,
    [Parameter(Mandatory = $True)]
    [string]$OutputDCRName,
    [Parameter(Mandatory = $False)]
    [bool]$OutputVerbose=$False,
    [Parameter(Mandatory = $True)]
    [String]$AzureEnvironment = "AzureCloud"
)

# Telemetry level.
$Debug = "Debug"
$Verbose = "Verbose"
$Informational = "Informational"
$Warning = "Warning"
$ErrorLvl = "Error"

$Succeeded = "Succeeded"
$Failed = "Failed"

# ARM resource types.
$VMResourceType = "virtualMachines";
$ArcVMResourceType = "machines";

# API versions.
$LogAnalyticsWorkspaceApiVersion = "2015-11-01-preview"
$ARMDepoymentApiVersion = "2021-04-01"
$VirtualMachineExtensionApiVersion = "2024-07-01"
$ArcMachineExtensionApiVersion = "2024-07-10"
$LatestLogAnalyticsWorkspaceApiVersion = "2023-09-01"

# AMA Agent And CT Extension values.
$ArcExtensionType = "Microsoft.HybridCompute/machines/extensions"
$AzureExtensionType = "Microsoft.Compute/virtualmachines/extensions"
$CTWindowsExtensionName = "ChangeTracking-Windows"
$CTLinuxExtensionName = "ChangeTracking-Linux"
$AMAWindowsExtensionName = "AzureMonitorWindowsAgent"
$AMALinuxExtensionName = "AzureMonitorLinuxAgent"
$SolutionsApiVersion = "2015-11-01-preview"

# HTTP methods.
$GET = "GET"
$PATCH = "PATCH"
$PUT = "PUT"
$POST = "POST"
$DELETE = "DELETE"

# ARM endpoints.
$WindowsRegistrySettingsPath = "{0}/datasources?`$filter=kind+eq+%27ChangeTrackingDefaultRegistry%27"
$WindowsTrackingServicesPath = "{0}/datasources?`$filter=kind+eq+%27ChangeTrackingServices%27"
$WindowsFileSettingsPath = "{0}/datasources?`$filter=kind+eq+%27ChangeTrackingCustomPath%27"
$LinuxFileSettingsPath = "{0}/datasources?`$filter=kind+eq+%27ChangeTrackingLinuxPath%27"
$DataTypeConfigurationPath = "{0}/datasources?`$filter=kind+eq+%27ChangeTrackingDataTypeConfiguration%27"
$ARMDeploymentPath = "/subscriptions/{0}/resourcegroups/{1}/providers/Microsoft.Resources/deployments/{2}"
$AssignDCRPath = "{0}/providers/Microsoft.Insights/dataCollectionRuleAssociations/{1}"
$GetExtensionsPath = "{0}/extensions"
$SolutionsWithWorkspaceFilterPath = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationsManagement/solutions?`$filter=properties/workspaceResourceId%20eq%20'{2}'"

# Validation values.
$TelemetryLevels = @($Debug, $Verbose, $Informational, $Warning, $ErrorLvl)
$HttpMethods = @($GET, $PATCH, $POST, $PUT, $DELETE)

# MMA Agent Types
$MMAAgentTypes = @("MicrosoftMonitoringAgent", "OmsAgentForLinux")

# DCR assocation Tag.
$MigrationTag = "CTMig"

#Max depth of payload.
$MaxDepth = 32

# Beginning of Payloads.

$DeployDCRARMTemplate = @"
{
  "properties": {
    "mode": "Incremental",
    "template": {
    },
    "parameters": {
      "workspaceLocation": {
        "value": null
      },
      "dataCollectionRuleName": {
        "value": null
      },
      "workspaceResourceId": {
        "value": null
      }
    }
  }
}
"@

$DeployChangeTrackingSolutionARMTemplate = @"
{
  "properties": {
    "mode": "Incremental",
    "template": {
      "`$schema": "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
      "contentVersion": "1.0.0.0",
      "parameters": {
        "subscriptionId": {
          "defaultValue": "",
          "type": "String"
        },
        "resourcegroupName": {
          "defaultValue": "",
          "type": "String"
        },
        "location": {
          "defaultValue": "",
          "type": "String"
        },
        "workspaceName": {
          "defaultValue": "",
          "type": "String"
        },
        "solutionType": {
          "defaultValue": "",
          "type": "String"
        }
      },
      "variables": {},
      "resources": [
        {
          "type": "Microsoft.OperationsManagement/solutions",
          "apiVersion": "2015-11-01-preview",
          "name": "[Concat(parameters('solutionType'), '(', parameters('workspaceName'), ')')]",
          "location": "[parameters('location')]",
          "plan": {
            "name": "[Concat(parameters('solutionType'), '(', parameters('workspaceName'), ')')]",
            "product": "[Concat('OMSGallery/', parameters('solutionType'))]",
            "promotionCode": "",
            "publisher": "Microsoft"
          },
          "properties": {
            "workspaceResourceId": "[Concat('/subscriptions/', parameters('subscriptionId'), '/resourceGroups/', parameters('resourcegroupName'), '/providers/Microsoft.OperationalInsights/workspaces/', parameters('workspaceName'))]"
          },
          "id": "[Concat('/subscriptions/', parameters('subscriptionId'), '/resourceGroups/', parameters('resourcegroupName'), '/providers/Microsoft.OperationsManagement/solutions/', parameters('solutionType'), '(', parameters('workspaceName'), ')')]"
        }
      ]
    },
    "parameters": {
      "subscriptionId": {
        "value": null
      },
      "resourcegroupName": {
        "value": null
      },
      "location": {
        "value": null
      },
      "workspaceName": {
        "value": null
      },
      "solutionType": {
        "value": null
      }
    }
  }
}
"@

$AssignDCRARMTemplate = @"
{
  "properties": {
    "mode": "Incremental",
    "template": {
      "`$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
      "contentVersion": "1.0.0.0",
      "parameters": {},
      "variables": {},
      "resources": [
        {
          "type": "Microsoft.Insights/dataCollectionRuleAssociations",
          "apiVersion": "2022-06-01",
          "name": null,
          "properties": {
            "dataCollectionRuleId": null
          },
          "scope": null
        },
        {
          "type": null,
          "apiVersion": null,
          "name": null,
          "location": null,
          "dependsOn": [
          ],
          "properties": {
            "publisher": "Microsoft.Azure.ChangeTrackingAndInventory",
            "type": null,
            "typeHandlerVersion": "2.27",
            "autoUpgradeMinorVersion": true
          }
        },
        {
          "type": null,
          "apiVersion": null,
          "name": null,
          "location": null,
          "dependsOn": [
          ],
          "properties": {
            "publisher": "Microsoft.Azure.Monitor",
            "type": null,
            "typeHandlerVersion": "1.30",
            "autoUpgradeMinorVersion": true
          }
        }
      ],
      "outputs": {}
    }
  }
}
"@

# End of Payloads.

$MachinesOnboaredToChangeTrackingQuery = 'Heartbeat | where Category == "Direct Agent" | where Solutions contains "changeTracking" | distinct Computer, ResourceId, ResourceType, OSType'
$Global:Machines = [System.Collections.ArrayList]@()
$Global:CTv2JsonObject = $null
$Global:DCRResourceId = $null
$Global:OutputDCRLocation = $null

function Write-Telemetry {
    <#
    .Synopsis
        Writes telemetry to the job logs.
        Telemetry levels can be "Informational", "Warning", "Error" or "Verbose".
    
    .PARAMETER Message
        Log message to be written.
    
    .PARAMETER Level
        Log level.

    .EXAMPLE
        Write-Telemetry -Message Message -Level Level.
    #>
    param (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$Message,
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateScript({ $_ -in $TelemetryLevels })]
        [String]$Level = $Informational
    )
	
    if ($Level -eq $Informational) {
        Write-Host $Message -ForegroundColor Green
    }
    if ($Level -eq $Warning) {
        Write-Warning $Message
    }
    elseif ($Level -eq $ErrorLvl) {
        Write-Error $Message
    }
    elseif ($OutputVerbose -eq $true) {
        Write-Verbose $Message -Verbose
    }
}

function Parse-ArmId {
    <#
        .SYNOPSIS
            Parses ARM resource id.
    
        .DESCRIPTION
            This function parses ARM id to return subscription, resource group, resource name, etc.
    
        .PARAMETER ResourceId
            ARM resourceId of the machine.      
    
        .EXAMPLE
            Parse-ArmId -ResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    param (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$ResourceId
    )
	
    $parts = $ResourceId.Split("/")
    return @{
        Subscription     = $parts[2]
        ResourceGroup    = $parts[4]
        ResourceProvider = $parts[6]
        ResourceType     = $parts[7]
        ResourceName     = $parts[8]
    }
}


function Invoke-RetryWithOutput {
    <#
        .SYNOPSIS
            Generic retry logic.
    
        .DESCRIPTION
            This command will perform the action specified until the action generates no errors, unless the retry limit has been reached.
    
        .PARAMETER Command
            Accepts an Action object.
            You can create a script block by enclosing your script within curly braces.     
    
        .PARAMETER Retry
            Number of retries to attempt.
    
        .PARAMETER Delay
            The maximum delay (in seconds) between each attempt. The default is 5 seconds.
    
        .EXAMPLE
            $cmd = { If ((Get-Date) -lt (Get-Date -Second 59)) { Get-Object foo } Else { Write-Host 'ok' } }
            Invoke-RetryWithOutput -Command $cmd -Retry 61
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [ScriptBlock]$Command,
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateRange(0, [UInt32]::MaxValue)]
        [UInt32]$Retry = 3,
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateRange(0, [UInt32]::MaxValue)]
        [UInt32]$Delay = 5
    )
	
    $ErrorActionPreferenceToRestore = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
	
    for ($i = 0; $i -lt $Retry; $i++) {
        $exceptionMessage = ""
        try {
            Write-Telemetry -Message ("[Debug]Command [{0}] started. Retry: {1}." -f $Command, ($i + 1) + $ForwardSlashSeparator + $Retry) -Level $Verbose
            $output = Invoke-Command $Command
            Write-Telemetry -Message ("[Debug]Command [{0}] succeeded." -f $Command) -Level $Verbose
            $ErrorActionPreference = $ErrorActionPreferenceToRestore
            return $output
        }
        catch [Exception] {
            $exceptionMessage = $_.Exception.Message
			
            if ($Global:Error.Count -gt 0) {
                $Global:Error.RemoveAt(0)
            }
			
            if ($i -eq ($Retry - 1)) {
                $message = ("[Debug]Command [{0}] failed even after [{1}] retries. Exception message:{2}." -f $command, $Retry, $exceptionMessage)
                Write-Telemetry -Message $message -Level $ErrorLvl
                $ErrorActionPreference = $ErrorActionPreferenceToRestore
                throw $message
            }
			
            $exponential = [math]::Pow(2, ($i + 1))
            $retryDelaySeconds = ($exponential - 1) * $Delay # Exponential Backoff Max == (2^n)-1
            Write-Telemetry -Message ("[Debug]Command [{0}] failed. Retrying in {1} seconds, exception message:{2}." -f $command, $retryDelaySeconds, $exceptionMessage) -Level $Warning
            Start-Sleep -Seconds $retryDelaySeconds
        }
    }
}

function Invoke-AzRestApiWithRetry {
    <#
        .SYNOPSIS
            Wrapper around Invoke-AzRestMethod.
    
        .DESCRIPTION
            This function calls Invoke-AzRestMethod with retries.
    
        .PARAMETER Params
            Parameters to the cmdlet.

        .PARAMETER Payload
            Payload.

        .PARAMETER Retry
            Number of retries to attempt.
    
        .PARAMETER Delay
            The maximum delay (in seconds) between each attempt. The default is 5 seconds.
            
        .EXAMPLE
            Invoke-AzRestApiWithRetry -Params @{SubscriptionId = "xxxx" ResourceGroup = "rgName" ResourceName = "resourceName" ResourceProvider = "Microsoft.Compute" ResourceType = "virtualMachines"} -Payload "{'location': 'westeurope'}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [System.Collections.Hashtable]$Params,
        [Parameter(Mandatory = $false, Position = 2)]
        [Object]$Payload = $null,
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateRange(0, [UInt32]::MaxValue)]
        [UInt32]$Retry = 3,
        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateRange(0, [UInt32]::MaxValue)]
        [UInt32]$Delay = 5
    )
	
    if ($Payload) {
        [void]$Params.Add('Payload', $Payload)
    }
	
    $retriableErrorCodes = @(429)
	
    for ($i = 0; $i -lt $Retry; $i++) {
        $exceptionMessage = ""
        $paramsString = $Params | ConvertTo-Json -Compress -Depth $MaxDepth | ConvertFrom-Json
        try {
            Write-Telemetry -Message ("[Debug]Invoke-AzRestMethod started with params [{0}]. Retry: {1}." -f $paramsString, ($i + 1) + $ForwardSlashSeparator + $Retry) -Level $Verbose
            $output = Invoke-AzRestMethod @Params -ErrorAction Stop
            $outputString = $output | ConvertTo-Json -Compress -Depth $MaxDepth | ConvertFrom-Json
            if ($retriableErrorCodes.Contains($output.StatusCode) -or $output.StatusCode -ge 500) {
                if ($i -eq ($Retry - 1)) {
                    $message = ("[Debug]Invoke-AzRestMethod with params [{0}] failed even after [{1}] retries. Failure reason:{2}." -f $paramsString, $Retry, $outputString)
                    Write-Telemetry -Message $message -Level $ErrorLvl
                    return Process-ApiResponse -Response $output
                }
				
                $exponential = [math]::Pow(2, ($i + 1))
                $retryDelaySeconds = ($exponential - 1) * $Delay # Exponential Backoff Max == (2^n)-1
                Write-Telemetry -Message ("[Debug]Invoke-AzRestMethod with params [{0}] failed with retriable error code. Retrying in {1} seconds, Failure reason:{2}." -f $paramsString, $retryDelaySeconds, $outputString) -Level $Warning
                Start-Sleep -Seconds $retryDelaySeconds
            }
            else {
                Write-Telemetry -Message ("[Debug]Invoke-AzRestMethod with params [{0}] succeeded. Output: [{1}]." -f $paramsString, $outputString) -Level $Verbose
                return Process-ApiResponse -Response $output
            }
        }
        catch [Exception] {
            $exceptionMessage = $_.Exception.Message
            Write-Telemetry -Message ("[Debug]Invoke-AzRestMethod with params [{0}] failed with an unhandled exception: {1}." -f $paramsString, $exceptionMessage) -Level $ErrorLvl
            throw
        }
    }
}

function Invoke-ArmApi-WithPath {
    <#
        .SYNOPSIS
            The function prepares payload for Invoke-AzRestMethod
    
        .DESCRIPTION
            This function prepares payload for Invoke-AzRestMethod.
    
        .PARAMETER Path
            ARM API path.

        .PARAMETER ApiVersion
            API version.

        .PARAMETER Method
            HTTP method.

        .PARAMETER Payload
            Paylod for API call.
    
        .EXAMPLE
            Invoke-ArmApi-WithPath -Path "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Compute/virtualMachines/{vmName}/start" -ApiVersion "2023-03-01" -method "PATCH" -Payload "{'location': 'westeurope'}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$Path,
        [Parameter(Mandatory = $true, Position = 2)]
        [String]$ApiVersion,
        [Parameter(Mandatory = $true, Position = 3)]
        [ValidateScript({ $_ -in $HttpMethods })]
        [String]$Method,
        [Parameter(Mandatory = $false, Position = 4)]
        [Object]$Payload = $null
    )
	
    $PathWithVersion = "{0}?api-version={1}"
    if ($Path.Contains("?")) {
        $PathWithVersion = "{0}&api-version={1}"
    }
	
    $Uri = ($PathWithVersion -f $Path, $ApiVersion)
    $Params = @{
        Path   = $Uri
        Method = $Method
    }
	
    return Invoke-AzRestApiWithRetry -Params $Params -Payload $Payload
}

function Process-ApiResponse {
    <#
        .SYNOPSIS
            Process API response and returns data.
    
        .PARAMETER Response
            Response object.
    
        .EXAMPLE
            Process-ApiResponse -Response {"StatusCode": 200, "Content": "{\"properties\": {\"location\": \"westeurope\"}}" }
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [Object]$Response
    )
	
    $successErrorCodes = @(200, 201, 202, 204)

    $content = $null
    if ($Response.Content) {
        $content = ConvertFrom-Json $Response.Content
    }
	
    if ($successErrorCodes.Contains($Response.StatusCode)) {
        return @{
            Status       = $Succeeded
            Response     = $content
            ErrorCode    = [String]::Empty
            ErrorMessage = [String]::Empty
        }
    }
    else {
        $errorCode = $Unknown
        $errorMessage = $Unknown
        if ($content.error) {
            $errorCode = ("{0}/{1}" -f $Response.StatusCode, $content.error.code)
            $errorMessage = $content.error.message
        }
		
        return @{
            Status       = $Failed
            Response     = $content
            ErrorCode    = $errorCode
            ErrorMessage = $errorMessage
        }
    }
}

function Get-MachinesFromLogAnalytics {
    <#
        .SYNOPSIS
            Gets machines onboarded to changeTracking solution from Log Analytics Workspace.
    
        .DESCRIPTION
            This command will return machines onboarded to changeTracking from LA workspace.

        .PARAMETER ResourceId
            Resource Id.

        .EXAMPLE
            Get-MachinesFromLogAnalytics -ResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$ResourceId
    )
	
    $armComponents = Parse-ArmId -ResourceId $ResourceId
    $script = {
        Set-AzContext -Subscription $armComponents.Subscription
        $Workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $armComponents.ResourceGroup -Name $armComponents.ResourceName
        $QueryResults = Invoke-AzOperationalInsightsQuery -WorkspaceId $Workspace.CustomerId -Query $MachinesOnboaredToChangeTrackingQuery -ErrorAction Stop
        return $QueryResults
    }
	
    $output = Invoke-RetryWithOutput -command $script
    return $output
}

function Populate-AllMachinesOnboardedToChangeTracking {
    <#
        .SYNOPSIS
            Gets all machines onboarded to changeTracking under this log analytics workspace.
    
        .DESCRIPTION
            This function gets all machines onboarded to changeTracking under this Log Analytics Workspace.
    
        .PARAMETER LogAnalyticsWorkspaceResourceId
            Log Analytics Workspace resource id.
    
        .EXAMPLE
            Populate-AllMachinesOnboardedToChangeTracking LogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$LogAnalyticsWorkspaceResourceId
    )
	
    try {
        $laResults = Get-MachinesFromLogAnalytics -ResourceId $LogAnalyticsWorkspaceResourceId
        if ($laResults.Results.Count -eq 0 -and $null -eq $laResults.Error) {
            Write-Telemetry -Message ("Zero machines retrieved from Log Analytics Workspace. If machines were recently onboarded, please wait for few minutes for machines to start reporting to Log Analytics Workspace") -Level $ErrorLvl
            throw
        }
        elseif ($laResults.Results.Count -gt 0 -or @($laResults.Results).Count -gt 0) {
            Write-Telemetry -Message ("Retrieved machines from Log Analytics Workspace.")
			
            foreach ($record in $laResults.Results) {
				
                if ($record.ResourceType -eq $ArcVMResourceType -or $record.ResourceType -eq $VMResourceType) {
                    $machineRecord = [PSCustomObject]@{
                        ResourceId = $record.ResourceId
                        OsType = $record.OSType
                        ResourceType = $record.ResourceType
                    }

                    [void]$Global:Machines.Add($machineRecord)
                }
            }
        }
        else {
            Write-Telemetry -Message ("Failed to get machines from Log Analytics Workspace with error {0}." -f $laResults.Error) -Level $ErrorLvl
            throw
        }
    }
    catch [Exception] {
        Write-Telemetry -Message ("Unhandled exception {0}." -f , $_.Exception.Message) -Level $ErrorLvl
        throw
    }
}

function Get-WindowsRegistrySettings {
    <#
        .SYNOPSIS
            Gets windows registry settings for legacy Change Tracking solution using Input Log Analytics Workspace and translates them to equivalent settings for latest Change Tracking solution using Output Log Analytics Workspace.
    
        .DESCRIPTION
            Gets windows registry settings for legacy Change Tracking solution using Input Log Analytics Workspace and translates them to equivalent settings for latest Change Tracking solution using Output Log Analytics Workspace.
    
        .PARAMETER LogAnalyticsWorkspaceResourceId
            Input Log Analytics Workspace Resource Id to get the CT settings from.
            
        .EXAMPLE
           Get-WindowsRegistrySettings LogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$LogAnalyticsWorkspaceResourceId
    )

    try {
        $ctv1RegistryResponse = Invoke-ArmApi-WithPath -Path ($WindowsRegistrySettingsPath -f $LogAnalyticsWorkspaceResourceId) -ApiVersion $LogAnalyticsWorkspaceApiVersion -Method $GET
        $registrySettings = New-Object System.Collections.ArrayList
        foreach ($object in $ctv1RegistryResponse.Response.value) {
            foreach ($objectProperties in $object.Properties) {
                $ctv2SettingObject = [PSCustomObject]@{
                    name        = ($object.name -replace ("-", "_"))
                    groupTag    = if ($objectProperties.groupTag -eq "") { "Recommended" } else { $objectProperties.groupTag }
                    enabled     = if ($objectProperties.enabled -eq "true") { $true } else { $false }
                    recurse     = if ($objectProperties.recurse -eq "true") { $true } else { $false }
                    description = ""
                    keyName     = ($objectProperties.keyName -replace ("\\{2}", "\"))
                    valueName   = $objectProperties.valueName
                }
                $registrySettings.Add($ctv2SettingObject) > $null
            }
        }
        $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[0].extensionSettings.registrySettings.registryInfo = $registrySettings
        Write-Telemetry -Message "Retrieved windows registry settings successfully"
    }
    catch [Exception] {
        $exceptionMessage = $_.Exception.Message
        Write-Telemetry -Message ("Retrieving windows registry settings failed with an unhandled exception: {0}." -f $exceptionMessage) -Level $ErrorLvl
    }
}

function Get-WindowsFileSetting {
    <#
        .SYNOPSIS
            Gets windows file settings for legacy Change Tracking solution using Input Log Analytics Workspace and translates them to equivalent settings for latest Change Tracking solution using Output Log Analytics Workspace.
    
        .DESCRIPTION
            Gets windows file settings for legacy Change Tracking solution using Input Log Analytics Workspace and translates them to equivalent settings for latest Change Tracking solution using Output Log Analytics Workspace.
    
        .PARAMETER LogAnalyticsWorkspaceResourceId
            Input Log Analytics Workspace Resource Id to get the CT settings from.
            
        .EXAMPLE
           Get-WindowsFileSetting LogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$LogAnalyticsWorkspaceResourceId
    )

    try {
        $ctv1FileResponse = Invoke-ArmApi-WithPath -Path ($WindowsFileSettingsPath -f $LogAnalyticsWorkspaceResourceId) -ApiVersion $LogAnalyticsWorkspaceApiVersion -Method $GET
        $fileSettingObjectList = New-Object System.Collections.ArrayList
        foreach ($object in $ctv1FileResponse.Response.value) {
            foreach ($objectProperties in $object.Properties) {
                $ctv2SettingObject = [PSCustomObject]@{
                    name                  = ($object.name -replace ("-", "_"))
                    enabled               = if ($objectProperties.enabled -eq "true") { $true } else { $false }
                    description           = ""
                    path                  = $objectProperties.path
                    recurse               = if ($objectProperties.recurse -eq "true") { $true } else { $false }
                    maxContentsReturnable = if ($objectProperties.maxContentsReturnable -eq 0) { 5000000 } else { $objectProperties.maxContentsReturnable }
                    maxOutputSize         = if ($objectProperties.maxOutputSize -eq 0) { 500000 } else { $objectProperties.maxOutputSize }
                    checksum              = $objectProperties.checksum
                    pathType              = $objectProperties.pathType
                    groupTag              = $objectProperties.groupTag
                }
                $fileSettingObjectList.Add($ctv2SettingObject) > $null
            }
        }
        $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[0].extensionSettings.fileSettings.fileinfo = $fileSettingObjectList
        Write-Telemetry -Message "Retrieved windows file settings successfully"
    }
    catch [Exception] {
        $exceptionMessage = $_.Exception.Message
        Write-Telemetry -Message ("Retrieving windows file settings failed with an unhandled exception: {0}." -f $exceptionMessage) -Level $ErrorLvl
    }
}

function Get-WindowsTrackingServices {
    <#
        .SYNOPSIS
            Gets windows tracking services settings for legacy Change Tracking solution using Input Log Analytics Workspace and translates them to equivalent settings for latest Change Tracking solution using Output Log Analytics Workspace.
    
        .DESCRIPTION
            Gets windows tracking services settings for legacy Change Tracking solution using Input Log Analytics Workspace and translates them to equivalent settings for latest Change Tracking solution using Output Log Analytics Workspace.
    
        .PARAMETER LogAnalyticsWorkspaceResourceId
            Input Log Analytics Workspace Resource Id to get the CT settings from.
            
        .EXAMPLE
           Get-WindowsTrackingServices LogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$LogAnalyticsWorkspaceResourceId
    )

    try {
        $ctv1FileResponse = Invoke-ArmApi-WithPath -Path ($WindowsTrackingServicesPath -f $LogAnalyticsWorkspaceResourceId) -ApiVersion $LogAnalyticsWorkspaceApiVersion -Method $GET
        # check if collectionTimeInterval is greater than 600 or not. if not make it 600(10 minutes)
        $cvtv1CollectionTimeInterval = if ($ctv1FileResponse.Response.value.properties.CollectionTimeInterval -gt 600) { $ctv1FileResponse.Response.value.properties.CollectionTimeInterval } else { 600 }
        $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[0].extensionSettings.servicesSettings.serviceCollectionFrequency = $cvtv1CollectionTimeInterval
        Write-Telemetry -Message "Retrieved windows tracking services settings successfully"
    }
    catch [Exception] {
        $exceptionMessage = $_.Exception.Message
        Write-Telemetry -Message ("Retrieving windows tracking services settings failed with an unhandled exception: {0}." -f $exceptionMessage) -Level $ErrorLvl
    }
}

function Get-LinuxFileSettings {
    <#
        .SYNOPSIS
            Gets linux file settings for legacy Change Tracking solution using Input Log Analytics Workspace and translates them to equivalent settings for latest Change Tracking solution using Output Log Analytics Workspace.
    
        .DESCRIPTION
            Gets linux file settings for legacy Change Tracking solution using Input Log Analytics Workspace and translates them to equivalent settings for latest Change Tracking solution using Output Log Analytics Workspace.
    
        .PARAMETER LogAnalyticsWorkspaceResourceId
            Input Log Analytics Workspace Resource Id to get the CT settings from.
            
        .EXAMPLE
           Get-LinuxFileSettings LogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$LogAnalyticsWorkspaceResourceId
    )

    try {
        $ctv1LinuxFileResponse = Invoke-ArmApi-WithPath -Path ($LinuxFileSettingsPath -f $LogAnalyticsWorkspaceResourceId) -ApiVersion $LogAnalyticsWorkspaceApiVersion -Method $GET
        $fileSettingObjectList = New-Object System.Collections.ArrayList
        foreach ($object in $ctv1LinuxFileResponse.Response.value) {
            foreach ($objectProperties in $object.Properties) {
                $ctv2SettingObject = [PSCustomObject]@{
                    name                  = ($object.name -replace ("-", "_"))
                    description           = ""
                    uploadContent         = $false
                    checksum              = "Sha256"
                    enabled               = if ($objectProperties.enabled -eq "true") { $true } else { $false }
                    destinationPath       = $objectProperties.destinationPath
                    useSudo               = if ($objectProperties.useSudo -eq "true") { $true } else { $false }
                    recurse               = if ($objectProperties.recurse -eq "true") { $true } else { $false }
                    maxContentsReturnable = if ($objectProperties.maxContentsReturnable -eq 0) { 5000000 } else { $objectProperties.maxContentsReturnable }
                    pathType              = $objectProperties.pathType
                    links                 = $objectProperties.links
                    maxOutputSize         = if ($objectProperties.maxOutputSize -eq 0) { 5 } else { $objectProperties.maxOutputSize }
                    groupTag              = $objectProperties.groupTag
                }
                $fileSettingObjectList.Add($ctv2SettingObject) > $null
            }
        }
        $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[1].extensionSettings.fileSettings.fileInfo = $fileSettingObjectList
        Write-Telemetry -Message "Retrieved linux file settings successfully"
    }
    catch [Exception] {
        $exceptionMessage = $_.Exception.Message
        Write-Telemetry -Message ("Retrieving linux file settings failed with an unhandled exception: {0}." -f $exceptionMessage) -Level $ErrorLvl
    }
}

function Get-DataTypeConfiguration {
    <#
        .SYNOPSIS
            Gets data type settings for legacy Change Tracking solution using Input Log Analytics Workspace and translates them to equivalent settings for latest Change Tracking solution using Output Log Analytics Workspace.
    
        .DESCRIPTION
            Gets data type settings for legacy Change Tracking solution using Input Log Analytics Workspace and translates them to equivalent settings for latest Change Tracking solution using Output Log Analytics Workspace.
    
        .PARAMETER LogAnalyticsWorkspaceResourceId
            Input Log Analytics Workspace Resource Id to get the CT settings from.
            
        .EXAMPLE
           Get-DataTypeConfiguration LogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$LogAnalyticsWorkspaceResourceId
    )

    try {
        $ctv1DatatypeConfigurationResponse = Invoke-ArmApi-WithPath -Path ($DataTypeConfigurationPath -f $LogAnalyticsWorkspaceResourceId) -ApiVersion $LogAnalyticsWorkspaceApiVersion -Method $GET
        foreach ($object in $ctv1DatatypeConfigurationResponse.Response.value) {
            if ($object.properties.DataTypeId -eq "Daemons") {
                $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[1].extensionSettings.enableServices = if ($object.Enabled -eq "false") { $false } else { $true }
            }
            if ($object.properties.DataTypeId -eq "Files") {
                $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[1].extensionSettings.enableFiles = if ($object.Enabled -eq "false") { $false } else { $true }
                $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[0].extensionSettings.enableFiles = if ($object.Enabled -eq "false") { $false } else { $true }
            }
            if ($object.properties.DataTypeId -eq "Inventory") {
                $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[1].extensionSettings.enableInventory = if ($object.Enabled -eq "false") { $false } else { $true }
                $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[0].extensionSettings.enableInventory = if ($object.Enabled -eq "false") { $false } else { $true }
            }
            if ($object.properties.DataTypeId -eq "Software") {
                $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[1].extensionSettings.enableSoftware = if ($object.Enabled -eq "false") { $false } else { $true }
                $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[0].extensionSettings.enableSoftware = if ($object.Enabled -eq "false") { $false } else { $true }
            }
            if ($object.properties.DataTypeId -eq "Registry") {
                $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[0].extensionSettings.enableRegistry = if ($object.Enabled -eq "false") { $false } else { $true }
                $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[1].extensionSettings.enableRegistry = $false
            }
            if ($object.properties.DataTypeId -eq "WindowsServices") {
                $Global:CTv2JsonObject.resources[0].properties.dataSources.extensions[0].extensionSettings.enableServices = if ($object.Enabled -eq "false") { $false } else { $true }
            }
        }
        Write-Telemetry -Message "Retrieved data type settings successfully"
    }
    catch [Exception] {
        $exceptionMessage = $_.Exception.Message
        Write-Telemetry -Message ("Retrieving data type settings failed with an unhandled exception: {0}." -f $exceptionMessage) -Level $ErrorLvl
    }
}

function Assign-DCR {
    <#
        .SYNOPSIS
            Assign DCR to machine and install AMA Agent and CT Extensions.
    
        .DESCRIPTION
            Assign DCR to machines and install AMA Agent and CT Extensions.
    
        .PARAMETER ResourceId
            ARM Resource Id of machine.

        .PARAMETER ResourceType
            Resource type of machine.

        .PARAMETER OsType
            Os type of machine.
            
        .EXAMPLE
            Assign-DCR -ResourceId $ResourceId -ResourceType $ResourceType -OsType $OsType
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$ResourceId,

        [Parameter(Mandatory = $true, Position = 2)]
        [String]$ResourceType,

        [Parameter(Mandatory = $true, Position = 3)]
        [String]$OsType
    )

    $armComponents = Parse-ArmId -ResourceId $ResourceId
    $dcrAssociationName = ($armComponents.ResourceName -replace "[^a-zA-Z0-9-]") + "_" + $MigrationTag
    $ctExtensionName = ($OsType -eq "windows") ? $CTWindowsExtensionName : $CTLinuxExtensionName
    $amaExtensionName = ($OsType -eq "windows") ? $AMAWindowsExtensionName : $AMALinuxExtensionName
    $extensionType = ($ResourceType -eq $ArcVMResourceType) ? $ArcExtensionType : $AzureExtensionType
    $apiVersion = ($ResourceType -eq $ArcVMResourceType) ? $ArcMachineExtensionApiVersion : $VirtualMachineExtensionApiVersion
    $dependsOnScope = ($AssignDCRPath -f $ResourceId, $dcrAssociationName)
    $amaTypeHandlerVersion = ($ResourceType -eq $VMResourceType -and $OsType -eq "linux") ? "1.0" : ($ResourceType -eq $ArcVMResourceType -and $OsType -eq "linux") ? "1.33" : "1.30"

    $resourceLocation = Invoke-ArmApi-WithPath -Path $ResourceId -ApiVersion $apiVersion -Method $GET

    # Assign DCR scope to machine.
    $assignDCRPayload = ConvertFrom-Json $AssignDCRARMTemplate
    $assignDCRPayload.properties.template.resources[0].name = $dcrAssociationName
    $assignDCRPayload.properties.template.resources[0].properties.dataCollectionRuleId = $Global:DCRResourceId
    $assignDCRPayload.properties.template.resources[0].scope = $ResourceId

    # Install CT extension on the machine and associate with DCR.
    $assignDCRPayload.properties.template.resources[1].type = $extensionType
    $assignDCRPayload.properties.template.resources[1].apiVersion = $apiVersion
    $assignDCRPayload.properties.template.resources[1].name = $armComponents.ResourceName + "/" + $ctExtensionName
    $assignDCRPayload.properties.template.resources[1].location = $resourceLocation.Response.location
    $dependsOn = [System.Collections.ArrayList]@()
    [void]$dependsOn.Add($dependsOnScope)
    $assignDCRPayload.properties.template.resources[1].dependsOn = $dependsOn
    $assignDCRPayload.properties.template.resources[1].properties.type = $ctExtensionName

     # Install AMA Agent on the machine and associate with DCR.
    $assignDCRPayload.properties.template.resources[2].type = $extensionType
    $assignDCRPayload.properties.template.resources[2].apiVersion = $apiVersion
    $assignDCRPayload.properties.template.resources[2].name = $armComponents.ResourceName + "/" + $amaExtensionName
    $assignDCRPayload.properties.template.resources[2].location = $resourceLocation.Response.location
    $dependsOn = [System.Collections.ArrayList]@()
    [void]$dependsOn.Add($dependsOnScope)
    $assignDCRPayload.properties.template.resources[2].dependsOn = $dependsOn
    $assignDCRPayload.properties.template.resources[2].properties.type = $amaExtensionName
    $assignDCRPayload.properties.template.resources[2].properties.typeHandlerVersion = $amaTypeHandlerVersion

    $assignDCRPayload = ConvertTo-Json -InputObject $assignDCRPayload -Depth $MaxDepth

    $assignDCRResponse = Invoke-ArmApi-WithPath -Path ($ARMDeploymentPath -f $armComponents.Subscription, $armComponents.ResourceGroup, $dcrAssociationName) -ApiVersion $ARMDepoymentApiVersion -Method $PUT -Payload $assignDCRPayload

    if ($assignDCRResponse.Status -eq $Succeeded)
    {
        do {
            $assignDCRResponse = Invoke-ArmApi-WithPath -Path ($ARMDeploymentPath -f $armComponents.Subscription, $armComponents.ResourceGroup, $dcrAssociationName) -ApiVersion $ARMDepoymentApiVersion -Method $GET
            if ($assignDCRResponse.Response.properties.provisioningState -eq $Failed) {
                Write-Telemetry -Message ("Failed to deploy assign DCR template {0} for machine {1} with below error." -f $dcrAssociationName, $ResourceId) -Level $ErrorLvl
                Write-Telemetry -Message ($assignDCRResponse.response.properties.error | ConvertTo-Json -Depth $MaxDepth) -Level $ErrorLvl
                throw
            }
        }
        while ($assignDCRResponse.Response.properties.provisioningState -ne $Succeeded) {       
        }

        Write-Telemetry -Message ("Assigned DCR Template and installed AMA Agent and CT Extension for machine {0}." -f $ResourceId)
    }
    else {
        Write-Telemetry -Message ("Failed to deploy assign DCR template {0} for machine {1} with below error." -f $dcrAssociationName, $ResourceId) -Level $ErrorLvl
        Write-Telemetry -Message ($assignDCRResponse.response.properties.error | ConvertTo-Json -Depth $MaxDepth) -Level $ErrorLvl
        throw
    }
}

function Associate-MachinesWithDCR {
    <#
        .SYNOPSIS
            Assign DCR to machines and install AMA Agent and CT Extensions.
    
        .DESCRIPTION
            Assign DCR to machines and install AMA Agent and CT Extensions.
        
        .EXAMPLE
            Associate-MachinesWithDCR
    #>

    foreach ($machine in $Global:Machines) {
        try {
            Assign-DCR -ResourceId $machine.ResourceId -ResourceType $machine.ResourceType -OSType $machine.OsType
        }
        catch [Exception] {
            Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        }
    }
}

function Remove-MMAAgent {
    <#
        .SYNOPSIS
            Removes MMA Agent from machine.
    
        .DESCRIPTION
            Removes MMA Agent from machine.
    
        .PARAMETER ResourceId
            ARM Resource Id of machine to remove MMA Agent.

        .PARAMETER ApiVersion
            Api version to use.
            
        .EXAMPLE
          Remove-MMAAgent -ResourceId $ResourceId -ApiVersion $ApiVersion
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$ResourceId,

        [Parameter(Mandatory = $true, Position = 2)]
        [String]$ApiVersion
    )

    $extensionsResponse = Invoke-ArmApi-WithPath -Path ($GetExtensionsPath -f $ResourceId) -ApiVersion $ApiVersion -Method $GET

    foreach ($extension in $extensionsResponse.Response.value)
    {
        if ($MMAAgentTypes.Contains($extension.properties.type)) {
            $removeExtensionResponse = Invoke-ArmApi-WithPath -Path $extension.id -ApiVersion $ApiVersion -Method $DELETE
            if ($removeExtensionResponse.Status -eq $Succeeded) {
                Write-Telemetry -Message ("Deleted {0}." -f $extension.id)
            }
            else {
                Write-Telemetry -Message ("Failed to delete {0} with error {1}." -f $extension.id, $removeExtensionResponse.ErrorMessage) -Level $ErrorLvl
            }
        }
    }
}

function Remove-MMAAgentFromMachines {
    <#
        .SYNOPSIS
            Removes MMA Agent from Input Log Analytics Workspace if Input and Output Log Analytics Workspaces are the same for migration.
    
        .DESCRIPTION
            Removes MMA Agent from Input Log Analytics Workspace if Input and Output Log Analytics Workspaces are the same for migration.
    
        .PARAMETER InputLogAnalyticsWorkspaceResourceId
            Input Log Analytics Workspace Resource Id.

        .PARAMETER OutputLogAnalyticsWorkspaceResourceId
            Output Log Analytics Workspace Resource Id.
            
        .EXAMPLE
          Remove-MMAAgentFromMachines -InputLogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}" -OutputLogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$InputLogAnalyticsWorkspaceResourceId,

        [Parameter(Mandatory = $true, Position = 2)]
        [String]$OutputLogAnalyticsWorkspaceResourceId
    )

    if ($InputLogAnalyticsWorkspaceResourceId -ne $OutputLogAnalyticsWorkspaceResourceId)
    {
        Write-Telemetry -Message ("Input and Output Log Analytics Workspaces are different.Not removing MMA agents." -f ($Global:DCRResourceId, $ResourceId))
        return
    }

    foreach ($machine in $Global:Machines) {
        try {

            if ($machine.ResourceType -eq $ArcVMResourceType) {

                Remove-MMAAgent -ResourceId $machine.ResourceId -ApiVersion $ArcMachineExtensionApiVersion
            }
            else {
                Remove-MMAAgent -ResourceId $machine.ResourceId -ApiVersion $VirtualMachineExtensionApiVersion
            }
        }
        catch [Exception] {
            Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        }
    }
}

function Deploy-ChangeTrackingSolutionARMTemplate {
    <#
        .SYNOPSIS
            Deploys Change Tracking solution to Output Log Analytics Workspace.
    
        .DESCRIPTION
            Deploys Change Tracking solution to Output Log Analytics Workspace.
    
        .PARAMETER InputLogAnalyticsWorkspaceResourceId
            Input Log Analytics Workspace Resource Id.

        .PARAMETER OutputLogAnalyticsWorkspaceResourceId
            Output Log Analytics Workspace Resource Id.
            
        .EXAMPLE
           Deploy-ChangeTrackingSolutionARMTemplate -InputLogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}" -OutputLogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$InputLogAnalyticsWorkspaceResourceId,

        [Parameter(Mandatory = $true, Position = 2)]
        [String]$OutputLogAnalyticsWorkspaceResourceId
    )
    
    if ($InputLogAnalyticsWorkspaceResourceId -eq $OutputLogAnalyticsWorkspaceResourceId)
    {
        Write-Telemetry -Message "Input and Output Log Analytics Workspaces are same.Not required to deploy Change Tracking solution again."
        return
    }

    try {
        
        $armComponents = Parse-ArmId -ResourceId $OutputLogAnalyticsWorkspaceResourceId
        $changeTrackingArmTemplatePayload = ConvertFrom-Json $DeployChangeTrackingSolutionARMTemplate
        $changeTrackingArmTemplatePayload.properties.parameters.subscriptionId.value = $armComponents.Subscription
        $changeTrackingArmTemplatePayload.properties.parameters.resourcegroupName.value = $armComponents.ResourceGroup
        $changeTrackingArmTemplatePayload.properties.parameters.location.value = $Global:OutputDCRLocation
        $changeTrackingArmTemplatePayload.properties.parameters.workspaceName.value = $armComponents.ResourceName
        $changeTrackingArmTemplatePayload.properties.parameters.solutionType.value = "ChangeTracking"
        $deploymentName = "DeployCTSolution_" + $MigrationTag + "_" + (New-Guid).Guid.ToString()

        $changeTrackingArmTemplatePayload = ConvertTo-Json -InputObject $changeTrackingArmTemplatePayload -Depth $MaxDepth | %{
            [Regex]::Replace($_, 
                "\\u(?<Value>[a-zA-Z0-9]{4})", {
                    param($m) ([char]([int]::Parse($m.Groups['Value'].Value,
                        [System.Globalization.NumberStyles]::HexNumber))).ToString() } )}

        $changeTrackingArmTemplateResponse = Invoke-ArmApi-WithPath -Path ($ARMDeploymentPath -f $armComponents.Subscription, $armComponents.ResourceGroup, $deploymentName) -ApiVersion $ARMDepoymentApiVersion -Method $PUT -Payload $changeTrackingArmTemplatePayload
        if ($changeTrackingArmTemplateResponse.Status -eq $Succeeded)
        {
            do {
                $changeTrackingArmTemplateResponse = Invoke-ArmApi-WithPath -Path ($ARMDeploymentPath -f $armComponents.Subscription, $armComponents.ResourceGroup, $deploymentName) -ApiVersion $ARMDepoymentApiVersion -Method $GET
                if ($changeTrackingArmTemplateResponse.Response.properties.provisioningState -eq $Failed) {
                    Write-Telemetry -Message ("Failed to deploy change tracking solution template {0} with below error." -f $deploymentName) -Level $ErrorLvl
                    Write-Telemetry -Message ($changeTrackingArmTemplateResponse.response.properties.error | ConvertTo-Json -Depth $MaxDepth) -Level $ErrorLvl
                    throw
                }
            }
            while ($changeTrackingArmTemplateResponse.Response.properties.provisioningState -ne $Succeeded) {       
            }

            Write-Telemetry -Message "Deployed change tracking solution successfully."
        }
        else {
            Write-Telemetry -Message ("Failed to deploy change tracking solution template {0} with below error." -f $deploymentName) -Level $ErrorLvl
            Write-Telemetry -Message ($changeTrackingArmTemplateResponse.response.properties.error | ConvertTo-Json -Depth $MaxDepth) -Level $ErrorLvl
            throw
        }
    }
    catch [Exception] {
        Write-Telemetry -Message ("Unhandled exception {0} while deploying change tracking solution template." -f , $_.Exception.Message) -Level $ErrorLvl
        throw
    }    
}

function Deploy-DCRARMTemplate {
    <#
        .SYNOPSIS
            Deploys DCR ARM template.
    
        .DESCRIPTION
            Deploys DCR ARM template.
    
        .PARAMETER LogAnalyticsWorkspaceResourceId
            Log Analytics Workspace Resource Id.

        .PARAMETER OutputDCRName
            DCR name.
            
        .EXAMPLE
           Deploy-DCRARMTemplate LogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}" -OutputDCRName "DCRMig"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$LogAnalyticsWorkspaceResourceId,

        [Parameter(Mandatory = $true, Position = 2)]
        [String]$OutputDCRName
    )
    
    try {

        $armComponents = Parse-ArmId -ResourceId $LogAnalyticsWorkspaceResourceId
        $dcrArmTemplatePayload = ConvertFrom-Json $DeployDCRARMTemplate
        $dcrArmTemplatePayload.properties.template = $Global:CTv2JsonObject
        $dcrArmTemplatePayload.properties.parameters.workspaceLocation.value = $Global:OutputDCRLocation
        $dcrArmTemplatePayload.properties.parameters.dataCollectionRuleName.value = $OutputDCRName
        $dcrArmTemplatePayload.properties.parameters.workspaceResourceId.value = $LogAnalyticsWorkspaceResourceId
        $dcrArmTemplatePayload = ConvertTo-Json -InputObject $dcrArmTemplatePayload -Depth $MaxDepth
        $deploymentName = $OutputDCRName + "_" + $MigrationTag + "_" + (New-Guid).Guid.ToString()

        $dcrArmTemplateResponse = Invoke-ArmApi-WithPath -Path ($ARMDeploymentPath -f $armComponents.Subscription, $armComponents.ResourceGroup, $deploymentName) -ApiVersion $ARMDepoymentApiVersion -Method $PUT -Payload $dcrArmTemplatePayload
        if ($dcrArmTemplateResponse.Status -eq $Succeeded)
        {
            do {
                $dcrArmTemplateResponse = Invoke-ArmApi-WithPath -Path ($ARMDeploymentPath -f $armComponents.Subscription, $armComponents.ResourceGroup, $deploymentName) -ApiVersion $ARMDepoymentApiVersion -Method $GET
                if ($dcrArmTemplateResponse.Response.properties.provisioningState -eq $Failed) {
                    Write-Telemetry -Message ("Failed to deploy DCR template {0} with below error." -f $deploymentName) -Level $ErrorLvl
                    Write-Telemetry -Message ($dcrArmTemplateResponse.response.properties.error | ConvertTo-Json -Depth $MaxDepth) -Level $ErrorLvl
                    throw
                }
            }
            while ($dcrArmTemplateResponse.Response.properties.provisioningState -ne $Succeeded) {       
            }

            $Global:DCRResourceId = $dcrArmTemplateResponse.Response.properties.outputResources[0].id
            Write-Telemetry -Message ("Deployed DCR {0} successfully" -f $Global:DCRResourceId)
        }
        else {
            Write-Telemetry -Message ("Failed to deploy DCR template {0} with below error." -f $deploymentName) -Level $ErrorLvl
            Write-Telemetry -Message ($dcrArmTemplateResponse.response.properties.error | ConvertTo-Json -Depth $MaxDepth) -Level $ErrorLvl
            throw
        }
    }
    catch [Exception] {
        Write-Telemetry -Message ("Unhandled exception {0} while deploying DCR template." -f , $_.Exception.Message) -Level $ErrorLvl
        throw
    }
}

function Migrate-SettingsToDCR {
    <#
        .SYNOPSIS
            Gets all files, settings, tracking & registry for legacy Change Tracking solution using Input Log Analytics Workspace and translates them to equivalent settings for latest Change Tracking solution using Output Log Analytics Workspace.
    
        .DESCRIPTION
            Gets all files, settings, tracking & registry for legacy Change Tracking solution using Input Log Analytics Workspace and translates them to equivalent settings for latest Change Tracking solution using Output Log Analytics Workspace.
    
        .PARAMETER LogAnalyticsWorkspaceResourceId
            Input Log Analytics Workspace Resource Id to get the CT settings from.
            
        .EXAMPLE
            Migrate-SettingsToDCR LogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$LogAnalyticsWorkspaceResourceId
    )

    try {
        Get-WindowsRegistrySettings -LogAnalyticsWorkspaceResourceId $LogAnalyticsWorkspaceResourceId
        Get-WindowsFileSetting -LogAnalyticsWorkspaceResourceId $LogAnalyticsWorkspaceResourceId
        Get-WindowsTrackingServices -LogAnalyticsWorkspaceResourceId $LogAnalyticsWorkspaceResourceId
        Get-LinuxFileSettings -LogAnalyticsWorkspaceResourceId $LogAnalyticsWorkspaceResourceId
        Get-DataTypeConfiguration -LogAnalyticsWorkspaceResourceId $LogAnalyticsWorkspaceResourceId        
    }
    catch [Exception] {
        Write-Telemetry -Message ("Unhandled exception {0} while migrating settings to DCR." -f , $_.Exception.Message) -Level $ErrorLvl
        throw
    }
}

function Create-DCRARMTemplate {
    <#
        .SYNOPSIS
            Creates DCR ARM template for files, settings, tracking & registry for latest Change Tracking solution.
    
        .DESCRIPTION
            Creates DCR ARM template for files, settings, tracking & registry for latest Change Tracking solution.
    
        .PARAMETER OutputDCRName
            DCR Name.

        .PARAMETER OutputLogAnalyticsWorkspaceResourceId
            Log Analytics Workspace resource id with which DCR will be associated.
            
        .EXAMPLE
            Create-DCRARMTemplate -OutputDCRName "DCRMig" OutputLogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$OutputDCRName,

        [Parameter(Mandatory = $true, Position = 2)]
        [String]$OutputLogAnalyticsWorkspaceResourceId
    )

    try {
        $logAnalyticsWorkspaceResponse = Invoke-ArmApi-WithPath -Path $OutputLogAnalyticsWorkspaceResourceId -ApiVersion $LatestLogAnalyticsWorkspaceApiVersion -Method $GET
        $Global:OutputDCRLocation = $logAnalyticsWorkspaceResponse.Response.location    
    }
    catch [Exception] {
        Write-Telemetry -Message ("Unhandled exception {0} while getting log analytics location." -f , $_.Exception.Message) -Level $ErrorLvl
        throw
    }

    $schema = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
    $contentVersion = "1.0.0.0"
    $dcrTemplate =
    [ordered]@{
        "`$schema" = $schema;
        contentVersion = "$contentVersion"
        parameters     = [ordered]@{
            dataCollectionRuleName = [ordered]@{
                type         = "string"
                metadata     = [ordered]@{
                    description = "Specifies the name of the data collection rule to create."
                }
                defaultValue = "$OutputDCRName"
            }
            workspaceResourceId    = [ordered]@{
                type         = "string"
                metadata     = [ordered]@{
                    description = "Specifies the Azure resource ID of the Log Analytics workspace to use to store change tracking data."
                }
                defaultValue = "$OutputLogAnalyticsWorkspaceResourceId"
            }
            workspaceLocation      = [ordered]@{
                type         = "string"
                metadata     = [ordered]@{
                    description = "Specifies location of log analytic workspace"
                }
                defaultValue = "$Global:OutputDCRLocation"
            }
        }

        resources      = @(
            [ordered]@{
                type       = "Microsoft.Insights/dataCollectionRules"
                apiVersion = "2022-06-01"
                name       = "[parameters('dataCollectionRuleName')]"
                location   = "[parameters('workspaceLocation')]"
                properties = [ordered]@{
                    description  = "Data collection rule for CT."
                    dataSources  = [ordered]@{
                        extensions = @(
                            [ordered]@{
                                streams           = @(
                                    "Microsoft-ConfigurationChange",
                                    "Microsoft-ConfigurationChangeV2",
                                    "Microsoft-ConfigurationData"
                                )
                                extensionName     = "ChangeTracking-Windows"
                                extensionSettings = [ordered]@{
                                    enableFiles                = $true
                                    enableSoftware             = $true
                                    enableRegistry             = $true
                                    enableServices             = $true
                                    enableInventory            = $true
                                    registrySettings = [ordered]@{
                                        registryCollectionFrequency = 3000
                                        registryInfo                = @()
                                    }
                                    fileSettings               = [ordered]@{
                                        fileCollectionFrequency = 2700
                                        fileinfo                = @()
                                    }
                                    softwareSettings           = [ordered]@{
                                        softwareCollectionFrequency = 1800
                                    }
                                    inventorySettings          = [ordered]@{
                                        inventoryCollectionFrequency = 36000
                                    }
                                    servicesSettings           = [ordered]@{
                                        serviceCollectionFrequency = 1800
                                    }
                                }
                                name              = "CTDataSource-Windows"
                            },
                            [ordered]@{
                                streams           = @(
                                    "Microsoft-ConfigurationChange",
                                    "Microsoft-ConfigurationChangeV2",
                                    "Microsoft-ConfigurationData"
                                )
                                extensionName     = "ChangeTracking-Linux"
                                extensionSettings = [ordered]@{
                                    enableFiles       = $true
                                    enableSoftware    = $true
                                    enableRegistry    = $false
                                    enableServices    = $true
                                    enableInventory   = $true
                                    fileSettings      = [ordered]@{
                                        fileCollectionFrequency = 900
                                        fileInfo                = @()
                                    }
                                    softwareSettings  = [ordered]@{
                                        softwareCollectionFrequency = 300
                                    }
                                    inventorySettings = [ordered]@{
                                        inventoryCollectionFrequency = 36000
                                    }
                                    servicesSettings  = [ordered]@{
                                        serviceCollectionFrequency = 300
                                    }
                                }
                                name              = "CTDataSource-Linux"
                            }
                        )
                    }
                    destinations = [ordered]@{
                        logAnalytics = @(
                            [ordered]@{
                                workspaceResourceId = "[parameters('workspaceResourceId')]"
                                name                = "Microsoft-CT-Dest"
                            }
                        )
                    }
                    dataFlows    = @(
                        [ordered]@{
                            streams      = @(
                                "Microsoft-ConfigurationChange",
                                "Microsoft-ConfigurationChangeV2",
                                "Microsoft-ConfigurationData"
                            )
                            destinations = @(
                                "Microsoft-CT-Dest"
                            )
                        }
                    )
                }
            }
        )
    }

    $Global:CTv2JsonObject = New-Object -TypeName PSObject -Property $dcrTemplate
    Write-Telemetry -Message "DCR ARM Template Created"
}

function Remove-CTSolution
{
   <#
		.SYNOPSIS
			Removes Change Tracking solution from linked log analytics workspace.
	
		.DESCRIPTION
			Removes Change Tracking solution from linked log analytics workspace.

        .PARAMETER InputLogAnalyticsWorkspaceResourceId
            Input Log Analytics Workspace Resource Id.

        .PARAMETER OutputLogAnalyticsWorkspaceResourceId
            Output Log Analytics Workspace Resource Id.
            
        .EXAMPLE
           Remove-CTSolution -InputLogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}" -OutputLogAnalyticsWorkspaceResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{laName}"
	#>
	[CmdletBinding()]
	Param
	(
        [Parameter(Mandatory = $true, Position = 1)]
		[String]$InputLogAnalyticsWorkspaceResourceId,

        [Parameter(Mandatory = $true, Position = 2)]
		[String]$OutputLogAnalyticsWorkspaceResourceId
	)

    if ($InputLogAnalyticsWorkspaceResourceId -eq $OutputLogAnalyticsWorkspaceResourceId) {
        Write-Telemetry -Message "Not removing CT solution as input and output log analytics workspaces are the same"
        return
    }
    
    $linkedWorkspace = $InputLogAnalyticsWorkspaceResourceId
    $parts = $linkedWorkspace.Split("/")
    
    $response = Invoke-ArmApi-WithPath -Path ($SolutionsWithWorkspaceFilterPath -f $parts[2], $parts[4], $parts[8]) -ApiVersion $SolutionsApiVersion -Method $GET
    
    if ($response.Status -eq $Failed)
    {
        Write-Telemetry -Message ("Failed to get solutions for log analytics workspace {0} with error {1}." -f $linkedWorkspace, $response.ErrorMessage) -Level $ErrorLvl
        throw
    }
    
    foreach ($solution in $response.Response.value)
    {
        $name = ("ChangeTracking(" + $parts[8] + ")")
        if ($solution.name -eq $name )
        {
            $response = Invoke-ArmApi-WithPath -Path $solution.id -ApiVersion $SolutionsApiVersion -Method $DELETE
    
            if ($response.Status -eq $Failed)
            {
                Write-Telemetry -Message ("Failed to remove Change Tracking solution from linked log analytics workspace {0} with error {1}." -f $linkedWorkspace, $response.ErrorMessage) -Level $ErrorLvl
            }
            else
            {
                Write-Telemetry -Message ("Removed Change Tracking solution from linked log analytics workspace {0}." -f $linkedWorkspace)
            }
        }
    }
}

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Telemetry -Message ("his script requires Powershell version 7 or newer to run. Please see https://docs.microsoft.com/en-us/powershell/scripting/whats-new/migrating-from-windows-powershell-51-to-powershell-7?view=powershell-7.1.") -Level $ErrorLvl
    exit 1
}

$azConnect = Connect-AzAccount -SubscriptionId $InputLogAnalyticsWorkspaceResourceId.Split("/")[2] -Environment $AzureEnvironment
if ($null -eq $azConnect) {
    Write-Telemetry -Message ("Failed to connect to azure in first attempt. Will retry with DeviceCodeAuthentication.") -Level $ErrorLvl
    $azConnect = Connect-AzAccount -UseDeviceAuthentication -SubscriptionId $InputLogAnalyticsWorkspaceResourceId.Split("/")[2] -Environment $AzureEnvironment
    if ($null -eq $azConnect) {
        Write-Telemetry -Message ("Failed to connect to azure with DeviceCodeAuthentication also.") -Level $ErrorLvl
        throw
    }
}
else {
    Write-Telemetry -Message ("Successfully connected with account {0} to subscription {1}" -f $azConnect.Context.Account, $azConnect.Context.Subscription)
}

try {
    # Retrieve all machines onboarded to Change Tracking.
    Populate-AllMachinesOnboardedToChangeTracking -LogAnalyticsWorkspaceResourceId $InputLogAnalyticsWorkspaceResourceId

    # Create DCR ARM Template.
    Create-DCRARMTemplate -OutputDCRName $OutputDCRName -OutputLogAnalyticsWorkspaceResourceId $OutputLogAnalyticsWorkspaceResourceId 

    # Migrate Settings from LA Workspace to Output LA Workspace DCR.
    Migrate-SettingsToDCR -LogAnalyticsWorkspaceResourceId $InputLogAnalyticsWorkspaceResourceId

    # Deploy Change Tracking Solution to Output Log Analytics Workspace.
    Deploy-ChangeTrackingSolutionARMTemplate -InputLogAnalyticsWorkspaceResourceId $InputLogAnalyticsWorkspaceResourceId -OutputLogAnalyticsWorkspaceResourceId $OutputLogAnalyticsWorkspaceResourceId

    # Deploy DCR Template.
    Deploy-DCRARMTemplate -LogAnalyticsWorkspaceResourceId $OutputLogAnalyticsWorkspaceResourceId -OutputDCRName $OutputDCRName

    # Remove MMA Agent.
    Remove-MMAAgentFromMachines -InputLogAnalyticsWorkspaceResourceId $InputLogAnalyticsWorkspaceResourceId -OutputLogAnalyticsWorkspaceResourceId $OutputLogAnalyticsWorkspaceResourceId

    # Associate DCR with Machines.
    Associate-MachinesWithDCR

    # Remove CT Solution from Input Log Analytics Workspace.
    Remove-CTSolution -InputLogAnalyticsWorkspaceResourceId $InputLogAnalyticsWorkspaceResourceId -OutputLogAnalyticsWorkspaceResourceId $OutputLogAnalyticsWorkspaceResourceId
}
catch [Exception] {
    Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
}

