# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# These are the registry types that are accepted by the registry DSC resource
data regularExpression
{
    ConvertFrom-StringData -StringData @'

        blankString = \\(Blank\\)
        enabledOrDisabled = Enable(d)?|Disable(d)?

        # Match a exactly one ( the first ) hexcode in a string
        hexCode = \\b(0x[A-Fa-f0-9]{8}){1}\\b

        # Looks for an integer but is not hex
        leadingIntegerUnbound = \\b([0-9]{1,})\\b

        # The registry hive is not provided in a consistant format, so the search pattern needs
        # To account for optional character ranges
        registryHive = (Registry)?\\s?Hive\\s?:\\s*?(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)

        #registryPath      = ((Registry)?\\s*(Path|SubKey)\\s*:\\s*|^\\\\SOFTWARE)(\\\\)?\\w+(\\\\)\\w+(\\\\)?

        registryPath      = ((Registry)?\\s*(Path|SubKey)\\s*:\\s*|^\\\\SOFTWARE)(\\\\)?\\w+(\\\\)(\\w+(\\\\)?|\\sP)

        registryEntryType = Type\\s?:\\s*?REG_(SZ|BINARY|DWORD|QWORD|MULTI_SZ|EXPAND_SZ)(\\s{1,}|$)

        registryValueName = ^\\s*?Value\\s*?Name\\s*?:

        registryValueData = ^\\s*?Value\\s*?:
        # Extracts multi string values
        MultiStringNamedPipe = (?m)(^)(System|Software)(.+)$

        # Or is in a word boundary since it is a common pattern
        registryValueRange = (?<![\\w\\d])but|\\bor\\b|and|Possible values(?![\\w\\d])

        # This is need validate that a value is still a string even if it contains a number
        hardenUncPathValues = (RequireMutualAuthentication|RequireIntegrity)
'@
}

data dscRegistryValueType
{
    ConvertFrom-StringData -StringData @'
        REG_SZ         = String
        REG_BINARY     = Binary
        REG_DWORD      = Dword
        REG_QWORD      = Qword
        REG_MULTI_SZ   = MultiString
        REG_EXPAND_SZ  = ExpandableString
        Does Not Exist = Does Not Exist
        DWORD          = Dword
        Disabled       = Dword
        Enabled        = Dword
'@
}

data testExpression
{
    ConvertFrom-StringData -stringdata @'
    Red = Apple
    Yellow = Banana
'@
}

$SingleLineRegistryPath = 
     [ordered]@{
        Criteria = [ordered]@{ 
                        Contains = 'Criteria:'; 
                        After    = [ordered]@{ 
                                        Match  = '((HKLM|HKCU).*(?=Criteria:))';
                                        Select = '((HKLM|HKCU).*(?=Criteria:))'; 
                                        
                                    };
                        Before   = [ordered]@{
                                        Match = 'Criteria:.*(HKLM|HKCU)'
                                        Select = '((HKLM|HKCU).*(?=\sis))'
                                    } 
                    };
        
        Root     = [ordered]@{ 
                    Match    = '(HKCU|HKLM|HKEY_LOCAL_MACHINE)\\'; 
                    Select   = '((HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER).*)' 
                };
        
        Verify = [ordered]@{ 
                    Contains = 'Verify'; 
                    Select   = '((HKLM|HKCU).*(?=Verify))'
              };
    }

$SingleLineRegistryValueName = 
     [ordered]@{
     One = @{ Select = '(?<=If the value(\s*)?((for( )?)?)").*(")?((?=is.*R)|(?=does not exist))' };
     Two = [ordered]@{ Match = 'If the.+(registry key does not exist)'; Select = '"[\s\S]*?"' };
     Three = @{ Select = '(?<=If the value of\s")(.*)(?="\s.*R)|(?=does not exist)' };
     Four = @{ Select = '((?<=If the value\s)(.*)(?=is\sR))' };
     Five = [ordered]@{ Match = 'the policy value'; Select = '(?<=")(.*)(?="\sis)' };
     Six = @{ Select = '((?<=for\s).*)' };
     Seven = @{ Select = '(?<=filevalidation\\).*(?=\sis\sset\sto)' }
     }

$SingleLineRegistryValueType = 
     [ordered]@{
     One = @{ Select = '(?<={0}(") is not).*=' }; #'(?<={0}(\"")? is not ).*=' #$([regex]::escape($myString))
     Two = @{ Select =  '({0}"?\sis (?!not))(.*=)'; Group = 2 }; #'(?<={0}(")\sis).*='}; #'(?<={0}(\"")?\s+is ).*=' }; 
     #'(?<={0}(\"")?\s+is ).*=' };
     Three = @{ Select = '(?<=Verify\sa).*(?=value\sof)'};
     Four = @{ Select = 'registry key exists and the([\s\S]*?)value'; Group = 1 };
     Five = @{ Select = '(?<={0}`" is set to ).*`"'};
     Six = @{ Select = '((hkcu|hklm).*\sis\s(.*)=)'; Group = 3 };
     #Seven = @{ Select = 'does not exist, this is not a finding'; Return = 'Does Not Exist'}
     }

$SingleLineRegistryValueData = 
     [ordered]@{
     One = @{ Select = '(?<={0})(\s*)?=.*(?=(,|\())'};   #'(?<={0}(\s*)?=).*(?=(,|\())' };
     Two = @{ Select = '((?<=value\sof).*(?=for))' };
     Three = @{ Select = '((?<=set\sto).*(?=\(true\)))' };
     Four = @{ Select = "((?<=is\sset\sto\s)(`'|`")).*(?=(`'|`"))" };
     Five = @{ Select = "(?<={0}\s=).*"}
     }

