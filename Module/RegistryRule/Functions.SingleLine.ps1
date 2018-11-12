# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Main Functions
<#
    .SYNOPSIS
        Looks in the Check-Content element to see if it matches registry string.

    .PARAMETER CheckStrings
        Check-Content element
#>
function Test-SingleLineRegistryRule
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    if ($checkContent -match "(HKCU|HKLM|HKEY_LOCAL_MACHINE)\\")
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $true"
        $true
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $false"
        $false
    }
}
#endregion
#region Registry Path
<#
    .SYNOPSIS
        Extract the registry path from an office STIG string.

    .Parameter CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-SingleLineRegistryPath
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )
    
    #$fullRegistryPath = $CheckContent | Select-String -Pattern "((HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER).*)"

    $regPath = $Script:SingleLineRegistryPath.GetEnumerator() | ForEach-Object { Get-SLRegistryPath -CheckContent $CheckContent -Hashtable $_ }
    return $regPath
}
<#
    .SYNOPSIS
        Extract the registry path from an office STIG string.

    .Parameter CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-SLRegistryPath
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter(Mandatory = $true)]
        [psobject]
        $Hashtable

    )
    #$fullRegistryPath = $CheckContent | Select-String -Pattern "((HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER).*)"

    $fullRegistryPath = $CheckContent
    
    foreach($i in $Hashtable.Value.GetEnumerator()) 
    {  

    if ($i.Value.GetType().Name -eq 'OrderedDictionary') 
    {
        Get-SLRegistryPath -CheckContent $fullRegistryPath -Hashtable $i
    } 
    else
    {
        switch ($i.Key)
        {
            Contains
            { 
                if ($fullRegistryPath.ToString().Contains($i.Value)) 
                {
                    continue
                }
                else 
                { 
                    return 
                }
            }

            Match 
            { 
                if($fullRegistryPath -match $i.Value )
                {
                  continue
                }
                else
                {
                    return
                }
            }
            
            Select 
            { 
                
                $regEx =  '{0}' -f $i.Value
                #$result = [regex]::Matches($fullRegistryPath, $regEx)
                $result = $CheckContent | Select-String -Pattern $regEx
                $fullRegistryPath = $result.Matches[0].Value
            }
        }
    }
}
if ( -not [String]::IsNullOrEmpty( $fullRegistryPath ) )
{
    Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found path : $true"

    switch -Wildcard ($fullRegistryPath)
    {
        "*HKLM*" {$fullRegistryPath = $fullRegistryPath -replace "^HKLM", "HKEY_LOCAL_MACHINE"}

        "*HKCU*" {$fullRegistryPath = $fullRegistryPath -replace "^HKCU", "HKEY_CURRENT_USER"}

        "*Software Publishing Criteria" {$fullRegistryPath = $fullRegistryPath -replace 'Software Publishing Criteria$','Software Publishing'}
    }

    $fullRegistryPath = $fullRegistryPath.ToString().trim(' ', '.')

    Write-Verbose "[$($MyInvocation.MyCommand.Name)] Trimmed path : $fullRegistryPath"
}
else
{
    Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found path : $false"
    throw "Registry path was not found in check content."
}

return $fullRegistryPath
}
#endregion
#region Registry Type
<#
    .SYNOPSIS
        Extract the registry value type from an Office STIG string.

    .Parameter CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueTypeFromSingleLineStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

 
    $regValueType = $Script:SingleLineRegistryValueType.GetEnumerator() | ForEach-Object { Get-RegistryValueTypeFromSLStig -CheckContent $CheckContent -Hashtable $_ }    
    $result = $regValueType
    return $result
}

<#
    .SYNOPSIS
        Extract the registry value type from an Office STIG string.

    .Parameter CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueTypeFromSLStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter(Mandatory = $true)]
        [psobject]
        $Hashtable
    )
    
    $valueName = $Script:SingleLineRegistryValueName.GetEnumerator() | ForEach-Object { Get-RegistryValueNameFromSLStig -CheckContent $CheckContent -Hashtable $_ }

    if($valueName.Count -gt 0)
    {
        $valueName = [Regex]::Escape($valueName[0])
        #$valueName = $valueName[0]
    }
    $valueType = $CheckContent

    foreach($i in $Hashtable.Value.GetEnumerator()) 
    {  

        switch ($i.Key)
        {
            Contains
            { 
                if ($CheckContent.Contains($i.Value)) 
                {
                    continue
                }
                else 
                { 
                    return 
                }
            }

            Match 
            { 
                $regEx =  $i.Value -f [regex]::escape($valueName)
                $result = [regex]::Matches($CheckContent.ToString(), $regEx)
               if(-not $result)
                {
                  continue
                }
                else
                {
                    return $null
                }
            }
            
            Select 
            { 
                if ($valueName)
                {
                    $regEx =  $i.Value -f [regex]::escape($valueName)
                    $result = $CheckContent | Select-String -Pattern $regEx
                }
               
                if(-not $result.Matches)
                {
                    $msg = "I don't have a value"
                    return
                } 
                else
                {
                $valueType = $result.Matches[0].Value
                if($Hashtable.Value['Group'])
                {
                    Write-Verbose 'a group exists'
                }
            }
          }
    } #Switch
}#Foreach
     if($valueType)
     {
        $testA = $valueType.ToString().Replace('=', '').Replace('"', '')
        $testB = $valueType.Replace('=', '').Replace('"', '')
        $valueType = $testB
    
<#     if ($valueType -is [Microsoft.PowerShell.Commands.MatchInfo])
    {
        $valueType = $valueType.Matches.Value.Replace('=', '').Replace('"', '')
    }
 #>
    if ( -not [String]::IsNullOrWhiteSpace( $valueType.Trim() ) )
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]    Found Type : $valueType"

        $valueType = Test-RegistryValueType -TestValueType $valueType
        $return = $valueType.trim()
        #$return = $valueType[0].ValueType.Trim()

        Write-Verbose "[$($MyInvocation.MyCommand.Name)]  Trimmed Type : $valueType"
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found Type : $false"
        # If we get here, there is nothing to verify so return.
        return
    }

    $return
        }
    else
    {
        return $valueType
    }
}
#endregion
#region Registry Name
<#
    .SYNOPSIS
        Extract the registry value type from a string.

    .Parameter CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueNameFromSingleLineStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )
 
        $regValueName = $Script:SingleLineRegistryValueName.GetEnumerator() | ForEach-Object { Get-RegistryValueNameFromSLStig -CheckContent $CheckContent -Hashtable $_ }

    return $regValueName[0]
}
<#
    .SYNOPSIS
        Extract the registry value type from a string.

    .Parameter CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueNameFromSLStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter(Mandatory = $true)]
        [psobject]
        $Hashtable
    )
    
    #$valueName = $CheckContent | Select-String -Pattern '(?<=If the value(\s*)?((for( )?)?)").*(")?((?=is.*R)|(?=does not exist))'

    $valueName = $CheckContent
    
    foreach($i in $Hashtable.Value.GetEnumerator()) 
    {  

        switch ($i.Key)
        {
            Contains
            { 
                if ($CheckContent.Contains($i.Value)) 
                {
                    continue
                }
                else 
                { 
                    return 
                }
            }

            Match 
            { 
                if($CheckContent -match $i.Value )
                {
                  continue
                }
                else
                {
                    return
                }
            }
            
            Select 
            { 
                
                $regEx =  '{0}' -f $i.Value
                $result = $CheckContent | Select-String -Pattern $regEx
                $valueName = $result
            }
    } #Switch
}#Foreach

     if($valueName)
     {
        #$valueName = $valueName.Replace('"', '')
        $valueName = $valueName.Matches.Value.Replace('"', '')

        if ($valueName.Count -gt 1)
        {
            $valueName = $valueName[0]
        }

        if ( -not [String]::IsNullOrEmpty( $valueName ) )
        {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found Name : $valueName"

            $return = $valueName.trim()

            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Trimmed Name : $valueName"
        }
        else
        {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found Name : $false"
            return
        }
            $return
        }
    else
    {
        return $valueName
    }
}
#endregion
#region Registry Data
<#
    .SYNOPSIS
        Looks for multiple patterns in the value string to extract out the value to return or determine
        if additional processing is required. For example if an allowable range detected, additional
        functions need to be called to convert the text into powershell operators.

    .Parameter CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueDataFromSingleStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )
    
    $regValueData = $Script:SingleLineRegistryValueData.GetEnumerator() | ForEach-Object { Get-RegistryValueDataFromSLStig -CheckContent $CheckContent -Hashtable $_ }
    $result = $regValueData[0].ToString().Trim(' ')
    
    return $result
}
<#
    .SYNOPSIS
        Looks for multiple patterns in the value string to extract out the value to return or determine
        if additional processing is required. For example if an allowable range detected, additional
        functions need to be called to convert the text into powershell operators.

    .Parameter CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueDataFromSLStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter(Mandatory = $true)]
        [psobject]
        $Hashtable
    )

    $valueType = Get-RegistryValueTypeFromSingleLineStig -CheckContent $CheckContent
    
    if ($valueType -eq "Does Not Exist")
    {
        return
    }
    #$valueData = $CheckContent

    foreach($i in $Hashtable.Value.GetEnumerator()) 
    {  

        switch ($i.Key)
        {
            Contains
            { 
                if ($CheckContent.Contains($i.Value)) 
                {
                    continue
                }
                else 
                { 
                    return 
                }
            }

            Match 
            { 
                if($CheckContent -match $i.Value )
                {
                  continue
                }
                else
                {
                    return
                }
            }
            
            Select 
            { 
                #$regEx =  '{0}' -f $i.Value
                #$result = [regex]::Matches($CheckContent.ToString(), $regEx)
                $regEx =  $i.Value -f [regex]::escape($valueType)
                #$result = [regex]::Matches($CheckContent.ToString(), $regEx)
                $result = $CheckContent | Select-String -Pattern $regEx
                if($result.Count -gt 0)
                {
                    $valueData = $result[0]
                }
            }
    } #Switch
}#Foreach

    if($valueData.Matches)
    {
    $test = $valueData.Matches[0].Value.Replace(',', '').Replace('"', '')
    $valueData = $test
    if ( -not [String]::IsNullOrEmpty( $valueData ) )
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found Name : $valueData"

        #$return = $valueData.trim(" ", "'")
        $return = $valueData

        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Trimmed Name : $return"
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found Name : $false"
        return
    }

    $return
    }
    else
    {
        return $valueData
    }
}
#endregion
#region Ancillary functions
<#
    .SYNOPSIS
        Get the registry value string from the Office STIG format.

    .Parameter CheckContent
        An array of the raw sting data taken from the STIG setting.

    .Parameter Trim
        Trims the leading a trailing parts of the string that are not registry specific
#>
function Get-RegistryValueStringFromSingleLineStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter()]
        [switch]
        $Trim
    )

    [string] $registryLine = ( $checkContent | Select-String -Pattern "Criteria:")

    if ( -not [String]::IsNullOrEmpty( $registryLine ) )
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found Value : $true"
        $return = $registryLine.trim()
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found Value : $false"
        return
    }

    if ($trim)
    {
        <#
            Trim leading and trailing string that is not needed.
            Criteria: If the value of excel.exe is REG_DWORD = 1, this is not a finding.
            Criteria: If the value SomeValueNAme is REG_DWORD = 1, this is not a finding.
        #>
        $return = (
            $return -Replace "Criteria: If the value (of)*\s*|\s*,\s*this is not a finding.", ''
        )

        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Trimmed Value : $return"
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Trimmed Value : $return"
    }

    # The string returned from here is split on the space, so remove extra spaces.
    $return -replace "\s{2,}", " "
}

<#
    .SYNOPSIS
        Checks the registry string format to determine if it is in the Office STIG format.

    .Parameter CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Test-SingleLineStigFormat
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    if ($checkContent -match "HKLM|HKCU|HKEY_LOCAL_MACHINE\\")
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $true"
        $true
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $false"
        $false
    }
}
#endregion
