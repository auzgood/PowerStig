# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# These are the registry regular expresion types that are accepted by the registry DSC resource

$SingleLineRegistryValueName =
     [ordered]@{
     Eight = [ordered]@{ Match = 'If the REG_DWORD'; Select = '((?<=for\s")(.*)(?<="))'}; #Added for Outlook Stig - JJS
     }

$SingleLineRegistryValueType =
     [ordered]@{
     Eight = @{ Select = '((?<=If the\s)(.*)(?<=DWORD))'}; #Added for Outlook Stig - JJS
    }

$SingleLineRegistryValueData =
     [ordered]@{
     Six = [ordered]@{ Match = 'If the value PublishCalendarDetailsPolicy'; Select = '((?<=is\s)(.*)(?=\sor))'} #Added for Outlook Stig - JJS
    }
