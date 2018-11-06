# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1

$exclude = @($MyInvocation.MyCommand.Name,'Template.*.txt')
$supportFileList = Get-ChildItem -Path $PSScriptRoot -Exclude $exclude
foreach ($supportFile in $supportFileList)
{
    Write-Verbose "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}
# Header

<#
    .SYNOPSIS
        Convert the contents of an xccdf check-content element into a RegistryRule
    .DESCRIPTION
        The RegistryRule class is used to extract the registry settings
        from the check-content of the xccdf. Once a STIG rule is identified a
        registry rule, it is passed to the RegistryRule class for parsing
        and validation.
    .PARAMETER Key
        The registry key to be evaluated
    .PARAMETER ValueName
        The registry value name to be evaluated
    .PARAMETER ValueData
        The value data that should be appiled to the the ValueName
    .PARAMETER ValueType
        The type of registry value
    .PARAMETER Ensure
        A present or absent flag
#>
Class RegistryRule : Rule
{
    [string] $Key
    [string] $ValueName
    [string[]] $ValueData
    [string] $ValueType
    [ensure] $Ensure

    <#
        .SYNOPSIS
            Default constructor
        .DESCRIPTION
            Converts a xccdf stig rule element into a RegistryRule
        .PARAMETER StigRule
            The STIG rule to convert
    #>
    hidden RegistryRule ([xml.xmlelement] $StigRule)
    {
        $this.InvokeClass($StigRule)
        $this.SetKey()
        $this.SetValueName()
        $this.SetValueType()
        $this.SetDscResource()

        if ($this.IsHardCodedOrganizationValueTestString())
        {
            $OrganizationValueTestString = $this.GetHardCodedOrganizationValueTestString()
            $this.set_OrganizationValueTestString($OrganizationValueTestString)

            $this.SetOrganizationValueRequired()
        }
        else
        {
            # Get the trimmed version of the value data line.
            [string] $registryValueData = $this.GetValueData()

            # If a range is found on the value line, it needs further processing.
            if ($this.TestValueDataStringForRange($registryValueData))
            {
                # Set the OrganizationValueRequired flag to true so that a org level setting will be required.
                $this.SetOrganizationValueRequired()

                # Try to extract a test string from the range text.
                $OrganizationValueTestString = $this.GetOrganizationValueTestString($registryValueData)

                # If a test string was returned, add it.
                if ($null -ne $OrganizationValueTestString)
                {
                    $this.set_OrganizationValueTestString($OrganizationValueTestString)
                }
            }
            else
            {
                if ($this.IsHardCoded())
                {
                    $registryValueData = $this.GetHardCodedString()
                }
                elseif ($this.IsDataBlank($registryValueData))
                {
                    $this.SetIsNullOrEmpty()
                    $registryValueData = ''
                }
                elseif ($this.IsDataEnabledOrDisabled($registryValueData))
                {
                    $registryValueData = $this.GetValidEnabledOrDisabled(
                        $this.ValueType, $registryValueData
                    )
                }
                elseif ($this.IsDataHexCode($registryValueData))
                {
                    $registryValueData = $this.GetIntegerFromHex($registryValueData)
                }
                elseif ($this.IsDataInteger($registryValueData))
                {
                    $registryValueData = $this.GetNumberFromString($registryValueData)
                }
                elseif ($this.ValueType -eq 'MultiString')
                {
                    if ($registryValueData -match "see below")
                    {
                        $registryValueData = $this.GetMultiValueRegistryStringData($this.RawString)
                    }
                    else
                    {
                        $registryValueData = $this.FormatMultiStringRegistryData($registryValueData)
                    }
                }
                $this.Set_ValueData($registryValueData)
            }
        }
    }

    #region Methods

    static [RegistryRule[]] ConvertFromXccdf ($StigRule)
    {
        $ruleList = @()
        if ([RegistryRule]::HasMultipleRules($StigRule.rule.Check.('check-content')))
        {
            [string[]] $splitRules = [RegistryRule]::SplitMultipleRules($StigRule.rule.Check.('check-content'))
            foreach ($splitRule in $splitRules)
            {
                $StigRule.rule.Check.('check-content') = $splitRule
                $ruleList += [RegistryRule]::New($StigRule)
            }
        }
        else
        {
            $ruleList += [RegistryRule]::New($StigRule)
        }
        return $ruleList
    }


    <#
        .SYNOPSIS
            Extracts the registry key from the check-content and sets the value
        .DESCRIPTION
            Gets the registry key from the xccdf content and sets the value. If
            the registry key that is returned is not valid, the parser status is
            set to fail.
    #>
    [void] SetKey ()
    {
        $thisKey = Get-RegistryKey -CheckContent $this.SplitCheckContent

        if (-not $this.SetStatus($thisKey))
        {
            $this.set_Key($thisKey)
        }
    }

    <#
        .SYNOPSIS
            Extracts the registry value name from the check-content and sets
            the value
        .DESCRIPTION
            Gets the registry value name from the xccdf content and sets the
            value. If the registry value name that is returned is not valid,
            the parser status is set to fail.
    #>
    [void] SetValueName ()
    {
        $thisValueName = Get-RegistryValueName -CheckContent $this.SplitCheckContent

        if (-not $this.SetStatus($thisValueName))
        {
            $this.set_ValueName($thisValueName)
        }
    }

    <#
        .SYNOPSIS
            Extracts the registry value type from the check-content and sets
            the value
        .DESCRIPTION
            Gets the registry value type from the xccdf content and sets the
            value. If the registry value type that is returned is not valid,
            the parser status is set to fail.
    #>
    [void] SetValueType ()
    {
        $thisValueType = Get-RegistryValueType -CheckContent $this.SplitCheckContent

        if ($thisValueType -ne "Does Not Exist")
        {
            if (-not $this.SetStatus($thisValueType))
            {
                $this.set_ValueType($thisValueType)
            }
        }
        else
        {
            $this.SetEnsureFlag([Ensure]::Absent)
        }
    }

    <#
        .SYNOPSIS
            Tests the value data for a range of valid values
        .DESCRIPTION
            Tests the value data string for text that describes a list of valid
            values
        .PARAMETER ValueDataString
            The text to test
    #>
    [bool] TestValueDataStringForRange ([string] $ValueDataString)
    {
        return Test-RegistryValueDataContainsRange -ValueDataString $ValueDataString
    }

    <#
        .SYNOPSIS
            Extracts the registry value data from the check-content and sets
            the value
        .DESCRIPTION
            Gets the registry value data from the xccdf content and sets the
            value. If the registry value data that is returned is not valid,
            the parser status is set to fail.
    #>

    [string] GetValueData ()
    {
        return Get-RegistryValueData -CheckContent $this.SplitCheckContent
    }

    <#
        .SYNOPSIS
            Tests if the value data is supposed to be blank
        .DESCRIPTION
            Some stig settings state that a registry value, if it exists, is set
            to an empty value
        .PARAMETER ValueDataString
            The text to test
    #>
    [bool] IsDataBlank ([string] $ValueDataString)
    {
        return Test-RegistryValueDataIsBlank -ValueDataString $ValueDataString
    }

    <#
        .SYNOPSIS
            Tests if the value data is an enabled or disabled
        .DESCRIPTION
            Checks if a string contains the literal word Enabled or Disabled
        .PARAMETER ValueDataString
            The text to test
    #>
    [bool] IsDataEnabledOrDisabled ([string] $ValueDataString)
    {
        return Test-RegistryValueDataIsEnabledOrDisabled -ValueDataString $ValueDataString
    }

    <#
        .SYNOPSIS
            Get the valid version of the enabled or disabled
        .DESCRIPTION
            Get the valid version of the enabled or disabled, based on the the
            value type. A binary enabled, cannot accept the enabled string so
            the valid vaule needs to be returnd.
        .PARAMETER ValueType
            The value tyoe to evaluate
        .PARAMETER ValueData
            The value data to evaluate
    #>
    [string] GetValidEnabledOrDisabled ([string] $ValueType, [string] $ValueData)
    {
        return Get-ValidEnabledOrDisabled -ValueType $ValueType -ValueData $ValueData
    }

    <#
        .SYNOPSIS
            Checks if a string contains a hexadecimal number
        .DESCRIPTION
            Checks if a string contains a hexadecimal number
        .PARAMETER ValueDataString
            The text to test
    #>
    [bool] IsDataHexCode ([string] $ValueDataString)
    {
        return Test-RegistryValueDataIsHexCode -ValueDataString $ValueDataString
    }

    <#
        .SYNOPSIS
            Returns the integer of a hexadecimal number
        .DESCRIPTION
            Extracts the hex code if it exists, convert to int32 and set the
            output value. This ignores the int that usually accompanies the
            hex value in parentheses.
        .PARAMETER ValueDataString
            The text to test
    #>
    [int] GetIntegerFromHex ([string] $ValueDataString)
    {
        return Get-IntegerFromHex -ValueDataString $ValueDataString
    }

    <#
        .SYNOPSIS
            Tests if the registry value is an integer
        .DESCRIPTION
            This will match any lines that start with an integer (of any length)
            as the value to be set
        .PARAMETER ValueDataString
            The text to test
    #>
    [bool] IsDataInteger ([string] $ValueDataString)
    {
        return Test-RegistryValueDataIsInteger -ValueDataString $ValueDataString
    }

    <#
        .SYNOPSIS
            Returns the number from a string
        .DESCRIPTION
            Returns the number from a string
        .PARAMETER ValueDataString
            The text to test
    #>
    [string] GetNumberFromString ([string] $ValueDataString)
    {
        return Get-NumberFromString -ValueDataString $ValueDataString
    }

    <#
        .SYNOPSIS
            Formats a string value into a multiline string
        .DESCRIPTION
            Formats a string value into a multiline string by spliting it on a
            space or comma space format
        .PARAMETER ValueDataString
            The text to test
    #>
    [string[]] FormatMultiStringRegistryData ([string] $ValueDataString)
    {
        return Format-MultiStringRegistryData -ValueDataString $ValueDataString
    }

    <#
        .SYNOPSIS
            Get the multi-value string data
        .DESCRIPTION
            Get the multi-value string data
        .PARAMETER CheckStrings
            The rule text from the check-content element in the xccdf
    #>
    [string[]] GetMultiValueRegistryStringData ([string[]] $CheckStrings)
    {
        return Get-MultiValueRegistryStringData -CheckStrings $CheckStrings
    }

    <#
        .SYNOPSIS
            Sets the ensure flag to the provided value
        .DESCRIPTION
            Sets the ensure flag to the provided value
        .PARAMETER EnsureFlag
            The value the Ensure flag should be set to
    #>
    [void] SetEnsureFlag ([Ensure] $Ensure)
    {
        $this.Ensure = $Ensure
    }

    hidden [void] SetDscResource ()
    {
        if ($this.Key -match "(^hklm|^HKEY_LOCAL_MACHINE)")
        {
            $this.DscResource = "xRegistry"
        }
        else
        {
            $this.DscResource = "cAdministrativeTemplate"
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if
        (
            (
                $CheckContent -Match "HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER" -and
                $CheckContent -NotMatch "Permission(s|)" -and
                $CheckContent -NotMatch "SupportedEncryptionTypes" -and
                $CheckContent -NotMatch "Sql Server" -and
                $CheckContent -NotMatch "v1607 of Windows 10" -and
                $CheckContent -NotMatch "Filestream"
            ) -or
            (
                $CheckContent -Match "Windows Registry Editor" -and
                $CheckContent -Match "HKLM|HKCU"
            ) -or
            (
                $CheckContent -match "HKLM|HKCU" -and
                $CheckContent -match "REG_DWORD"
            )
        )
        {
            return $true
        }
        return $false
    }

    <#
        .SYNOPSIS
            Tests if a rule contains multiple checks
        .DESCRIPTION
            Search the rule text to determine if multiple registry paths are defined
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>
    static [bool] HasMultipleRules ([string] $CheckContent)
    {
        return Test-MultipleRegistryEntries -CheckContent ([Rule]::SplitCheckContent($CheckContent))
    }

    <#
        .SYNOPSIS
            Splits a rule into multiple checks
        .DESCRIPTION
            Once a rule has been found to have multiple checks, the rule needs
            to be split. This method splits registry paths into multiple rules.
            Each split rule id is appended with a dot and letter to keep reporting
            per the ID consistent. An example would be is V-1000 contained 2
            checks, then SplitMultipleRules would return 2 objects with rule ids
            V-1000.a and V-1000.b
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>
    static [string[]] SplitMultipleRules ([string] $CheckContent)
    {
        return (Split-MultipleRegistryEntries -CheckContent ([Rule]::SplitCheckContent($CheckContent)))
    }

    #endregion
}
