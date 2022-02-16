<#
.SYNOPSIS
    pwshf5.psm1
.DESCRIPTION
    A REST-based module for interacting with the F5 Network interface iControlREST api.
.NOTES
    Created by: Cale Robertson
#>

function Get-F5Connection {
    param (
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $name
    )
    if ($name) {
        return $global:F5Connections[$name]
    }
    return $global:F5Connections
}

function Set-F5Connection {
    param (
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $url,

        [PSCredential][Parameter(Mandatory = $false)]
        $credential,

        [switch]
        $default,

        [switch]
        $allow_unencrypted,

        [switch]
        $force
    )
    # If the global variable doesn't already exist, create it.
    if (!$global:F5Connections -or ($global:F5Connections.Length -eq 1 -and $global:F5Connections.Count -eq 0)) {
        $global:F5Connections = @{}
        $default = $true
    }

    # If the connection already exists and we aren't using -force, throw a hissy fit.
    if ($global:F5Connections.Keys -contains $name -and !$force) {
        throw "ERROR: A connection named $name already exists, choose a different name or use the -force flag"
    }

    # If this connection is the new default, remove any existing default flags.
    if ($default) {
        foreach ($connection in $global:F5Connections.Keys) {
            $global:F5Connections[$connection].default = $false
        }
    }

    # If we're updating an existing connection that happens to be the default and we haven't flagged it as such, keep it as the default.
    if ($force) {
        if ($global:F5Connections[$name].default) {
            $default = $true
        }
    }

    $global:F5Connections[$name] = @{
        url               = $url.TrimEnd("/").Trim() + '/mgmt/tm'
        default           = $default
        allow_unencrypted = $allow_unencrypted
    }

    if ($credential) {
        $global:F5Connections[$name].credential = $credential
    }
}

# Remove a connection from the global variable.
function Remove-F5Connection {
    param (
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $name,

        [switch]
        $force
    )
    
    # If we don't specify a name, make sure -force is used to prevent accidental deletion of all configured connections.
    if (!$name -and !$force) {
        throw "ERROR: Calling this function without a name specified requires the -force flag as it will remove all existing connections."
    }

    if ($name) {
        if ($global:F5Connections) {
            $global:F5Connections.Remove($name)
        }
    } else {
        $global:F5Connections = $null
    }
}

function Get-F5DefaultConnection {
    if ($global:F5Connections) {
        foreach ($connection in $global:F5Connections.Keys) {
            if ($global:F5Connections[$connection].default) {
                return $global:F5Connections[$connection]
            }
        }
    }
    throw "ERROR: Unable to find default connection."
}

function Invoke-F5RestMethod {
    param (
        [Parameter(Mandatory = $true)]
        $request,

        [string][Parameter(Mandatory = $false)]
        $f5_connection,

        [string][Parameter(Mandatory = $false)]
        $transaction_id
    )

    # Retrive default connection if not specified.
    if (!$f5_connection) {
        $f5 = Get-F5DefaultConnection
    } else {
        $f5 = Get-F5Connection -name $f5_connection
    }

    # Prepend base url to relative uri.
    $request.Uri = $f5.url + $request.Uri

    # Use default creds if none are specified
    if ($f5.credential) {
        $request['Credential'] = $f5.credential
    } else {
        $request['UseDefaultCredentials'] = $true
    }

    # Allow unencrypted auth if specified
    if ($f5.allow_unencrypted) {
        $request['AllowUnencryptedAuthentication'] = $true
    }

    # If we're using a transaction id, add it to the request header.
    if ($transaction_id) {
        $req_headers = @{
            'X-F5-REST-Coordination-Id' = $transaction_id
        }
        $request['Headers'] = $req_headers
    }

    return Invoke-RestMethod @request
}

function New-F5Transaction {
    param (
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )
    
    $req = @{
        Uri         = '/transaction'
        Method      = 'POST'
        Body        = '{ }'
        ContentType = 'application/json'
    }

    $res = Invoke-F5RestMethod $req $f5_connection
    
    return $res.transId
}

function Get-F5Transaction {
    param (
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $id,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri         = "/transaction/$id"
        Method      = 'GET'
    }

    $res = Invoke-F5RestMethod $req $f5_connection
    
    return $res
}

function Get-F5TransactionCommands {
    param (
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $id,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri    = "/transaction/$id/commands"
        Method = 'GET'
    }

    $res = Invoke-F5RestMethod $req $f5_connection
    
    return $res.items
}

function Submit-F5Transaction {
    param (
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $id,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri    = "/transaction/$id"
        Method = 'PATCH'
        Body   = '{ "state":"VALIDATING" }'
    }

    $res = Invoke-F5RestMethod $req $f5_connection
    return $res
}

function Close-F5Transaction {
    param (
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $id,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri = "/transaction/$id"
        Method = 'DELETE'
    }

    $res = Invoke-F5RestMethod $req $f5_connection
    return $res
}

function Get-F5iRule {
    param(
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri    = '/ltm/rule'
        Method = 'GET'
    }

    # If we're only looking for a specific iRule
    if ($name) {
        $req.Uri += "/$name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$name) {
        return $res.items
    }
    return $res
}

function New-F5iRule {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $content,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req_body = @"
    {
        "name": "$name",
        "apiAnonymous": $content
    }
"@

    $req = @{
        Uri         = '/ltm/rule'
        Method      = 'POST'
        Body        = $req_body
        ContentType = 'application/json'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Update-F5iRule {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $content,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req_body = @"
    {
        "name": "$name",
        "apiAnonymous": $content
    }
"@

    $req = @{
        Uri         = "/ltm/rule/$name"
        Method      = 'PATCH'
        Body        = $req_body
        ContentType = 'application/json'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Remove-F5iRule {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,
        
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri    = "/ltm/rule/$name"
        Method = 'DELETE'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Get-F5VirtualServer {
    param(
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [switch]
        $expand_subcollections
    )

    $req = @{
        Uri    = '/ltm/virtual'
        Method = 'GET'
    }

    # If we're only looking for a specific pool
    if ($name) {
        $req.Uri += "/$name"
    }

    if ($expand_subcollections) {
        $req.Uri += '?expandSubcollections=true'
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$name) {
        return $res.items
    }
    return $res
}

function New-F5VirtualServer {
    param(
        [string][Parameter(Mandatory = $true, ParameterSetName = 'Blank')][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $true, ParameterSetName = 'FromConfig')][ValidateNotNullOrEmpty()]
        $config_json,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = '/ltm/virtual'
        Method      = 'POST'
        Body        = "{ `"name`":`"$name`" }"
        ContentType = 'application/json'
    }

    if ($PSCmdlet.ParameterSetName -eq 'FromConfig') {
        $req.Body = $config_json
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Edit-F5VirtualServer {
    param (
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [Parameter(Mandatory = $true)]
        $resource_definition,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = "/ltm/virtual/$name"
        Method      = 'PATCH'
        Body        = $resource_definition
        ContentType = 'application/json'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Add-F5VirtualServeriRule {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $irule_name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = "/ltm/virtual/$name"
        Method      = 'PATCH'
        ContentType = 'application/json'
    }

    # Get the existing virtual server object.
    $vs = Get-F5VirtualServer -name $name

    # Check if it already has existing rules.
    if ($vs.rules) {
        # Loop through each existing rule to ensure we're not trying to add a duplicate.
        foreach ($rule in $vs.rules) {
            if ($rule.TrimStart('/Common/') -eq $irule_name.TrimStart('/Common/')) {
                throw "ERROR: Virtual Server $($vs.name) already has iRule $irule_name attached."
            }
        }
        $rules_to_apply = @{
            rules = $vs.rules
        }
        # Add new rule to the end of existing rules.
        $rules_to_apply.rules += $irule_name
    } else {
        # If not existing rules, simply add our new rule.
        $rules_to_apply = @{
            rules = @($irule_name)
        }
    }

    $req['Body'] = $rules_to_apply | ConvertTo-Json

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Remove-F5VirtualServeriRule {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $irule_name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    ) 

    $req = @{
        Uri         = "/ltm/virtual/$name"
        Method      = 'PATCH'
        ContentType = 'application/json'
    }

    # Get the existing virtual server object.
    $vs = Get-F5VirtualServer -name $name

    # Check if it already has existing rules.
    if ($vs.rules) {
        $vs.rules
        $rules_to_apply = @{
            rules = [System.Collections.ArrayList]@($vs.rules)
        }

        if ($rules_to_apply.rules.Contains('/Common/' + $irule_name.TrimStart('/Common/'))) {
            $rules_to_apply.rules.Remove('/Common/' + $irule_name.TrimStart('/Common/'))
        } else {
            throw "ERROR: Virtual Server $($vs.name) does not contain irule $irule_name."
        }
        
    } else {
        throw "ERROR: Virtual Server $($vs.name) does not contain irule $irule_name."
    }

    $req['Body'] = $rules_to_apply | ConvertTo-Json

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Get-F5VirtualServerProfile {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,
        
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $profile_name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [switch]
        $expand_subcollections
    )

    $req = @{
        Uri    = "/ltm/virtual/$name/profiles"
        Method = 'GET'
    }

    # If we're only looking for a specific pool
    if ($profile_name) {
        $req.Uri += "/$profile_name"
    }

    if ($expand_subcollections) {
        $req.Uri += '?expandSubcollections=true'
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$profile_name) {
        return $res.items
    }
    return $res
}

function Get-F5VirtualServerPolicy {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $policy_name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [switch]
        $expand_subcollections
    )

    $req = @{
        Uri    = "/ltm/virtual/$name/policies"
        Method = 'GET'
    }

    # If we're only looking for a specific pool
    if ($policy_name) {
        $req.Uri += "/$policy_name"
    }

    if ($expand_subcollections) {
        $req.Uri += '?expandSubcollections=true'
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$policy_name) {
        return $res.items
    }
    return $res
}

function Add-F5VirtualServerProfile {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $profile_payload,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = "/ltm/virtual/$name/profiles"
        Method      = 'POST'
        ContentType = 'application/json'
        Body        = $profile_payload
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Add-F5VirtualServerPolicy {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $policy_name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = "/ltm/virtual/$name/policies"
        Method      = 'POST'
        ContentType = 'application/json'
        Body        = @{name = $policy_name} | ConvertTo-Json
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Remove-F5VirtualServer {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri    = "/ltm/virtual/$name"
        Method = 'DELETE'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Get-F5Pool {
    param(
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri    = '/ltm/pool'
        Method = 'GET'
    }

    # If we're only looking for a specific pool.
    if ($name) {
        $req.Uri += "/$name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$name) {
        return $res.items
    }
    return $res
}

function New-F5Pool {
    param(
        [string][Parameter(Mandatory = $true, ParameterSetName = 'Blank')][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $true, ParameterSetName = 'FromConfig')][ValidateNotNullOrEmpty()]
        $config_json,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = '/ltm/pool'
        Method      = 'POST'
        Body        = "{ `"name`":`"$name`" }"
        ContentType = 'application/json'
    }

    if ($PSCmdlet.ParameterSetName -eq 'FromConfig') {
        $req.Body = $config_json
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Remove-F5Pool {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri    = "/ltm/pool/$name"
        Method = 'DELETE'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Get-F5PoolMembers {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri    = "/ltm/pool/$name/members"
        Method = 'GET'
    }

    #Result will return members and current member status

    $res = Invoke-F5RestMethod $req $f5_connection

    return $res
}

function Set-F5PoolMemberState {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $member,

        [string][Parameter(Mandatory = $false)][ValidateSet('user-up','user-down')]
        $state = 'user-up',

        [string][Parameter(Mandatory = $false)][ValidateSet('user-enabled','user-disabled')]
        $session = 'user-enabled'
    )

    $req = @{
        Uri    = "/ltm/pool/$name/members/~Common~$member"
        Method = 'PUT'
        ContentType = 'application/json'
        body = "{ `"state`":`"$state`", `"session`":`"$session`" }"
    }

    #Default behaviour is to enable the pool member

    $res = Invoke-F5RestMethod $req $f5_connection

    return $res
}

function Get-F5Policy {
    param(
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [switch]
        $expand_subcollections,

        [switch]
        $draft
    )

    $req = @{
        Uri    = '/ltm/policy'
        Method = 'GET'
    }

    # If we're only looking for a specific pool
    if ($name) {
        if ($draft) {
            $req.Uri += "/~Common~Drafts~$name"
        } else {
            $req.Uri += "/$name"
        }
    }

    if ($expand_subcollections) {
        $req.Uri += '?expandSubcollections=true'
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$name) {
        return $res.items
    }
    return $res
}

function New-F5Policy {
    param(
        [string][Parameter(Mandatory = $true, ParameterSetName = 'Blank')][ValidateNotNullOrEmpty()]
        $name,

        [Parameter(Mandatory = $true, ParameterSetName = 'FromConfig')][ValidateNotNullOrEmpty()]
        $config_json,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id,

        [switch]
        $draft
    )

    $req = @{
        Uri         = '/ltm/policy'
        Method      = 'POST'
        ContentType = 'application/json'
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Blank' {
            if ($draft) {
                $req.Body = "{ `"name`":`"/Common/Drafts/$name`", `"strategy`":`"first-match`" }"
            } else {
                $req.Body = "{ `"name`":`"$name`", `"strategy`":`"first-match`" }"
            }
        }
        'FromConfig' {
            if ($draft) {
                $config_json = $config_json | ConvertFrom-Json
                $config_json.name = "/Common/Drafts/$($config_json.name)"
                $config_json = $config_json | ConvertTo-Json
            }
            $req.Body = $config_json
        }
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Copy-F5PolicyToDraft {
    param(
        [string][Parameter(Mandatory = $true, ParameterSetName = 'Blank')][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = "/ltm/policy/$name"
        Method      = 'PATCH'
        Body        = '{ "createDraft": true }'
        ContentType = 'application/json'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Edit-F5Policy {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $config_json,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id,

        [switch]
        $draft
    )

    $req = @{
        Uri         = "/ltm/policy/$name"
        Method      = 'PATCH'
        Body        = $config_json
        ContentType = 'application/json'
    }

    if ($draft) {
        $req.Uri = "/ltm/policy/~Common~Drafts~$name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Publish-F5PolicyDraft {
    param (
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = "/ltm/policy/~Common~Drafts~$name"
        Method      = 'POST'
        Body        = "{ `"command`":`"publish`", `"draftCopy`":`"$name`" }"
        ContentType = 'application/json'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id
    
    return $res
}

function Get-F5PolicyRule {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $policy_name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $rule_name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [switch]
        $draft
    )

    $req = @{
        Uri         = "/ltm/policy/$policy_name/rules/$rule_name"
        Method      = 'GET'
    }

    if ($draft) {
        $req.Uri = "/ltm/policy/~Common~Drafts~$policy_name/rules/$rule_name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$rule_name) {
        return $res.items
    }

    return $res
}

function Add-F5PolicyRule {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $policy_name,

        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $rule_name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $description,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id,

        [switch]
        $draft
    )

    $req = @{
        Uri         = "/ltm/policy/$policy_name/rules"
        Method      = 'POST'
        Body        = "{ `"name`":`"$rule_name`", `"description`":`"$description`" }"
        ContentType = 'application/json'
    }

    if ($draft) {
        $req.Uri = "/ltm/policy/~Common~Drafts~$policy_name/rules"
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Edit-F5PolicyRule {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $policy_name,

        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $rule_name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $config_json,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id,

        [switch]
        $draft
    )

    $req = @{
        Uri         = "/ltm/policy/$policy_name/rules/$rule_name"
        Method      = 'PATCH'
        Body        = $config_json
        ContentType = 'application/json'
    }

    if ($draft) {
        $req.Uri = "/ltm/policy/~Common~Drafts~$policy_name/rules/$rule_name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Remove-F5PolicyRule {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $policy_name,

        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $rule_name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id,

        [switch]
        $draft
    )

    $req = @{
        Uri         = "/ltm/policy/$policy_name/rules/$rule_name"
        Method      = 'DELETE'
    }

    if ($draft) {
        $req.Uri = "/ltm/policy/~Common~Drafts~$policy_name/rules/$rule_name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Remove-F5Policy {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id,

        [switch]
        $draft
    )

    $req = @{
        Uri    = "/ltm/policy/$name"
        Method = 'DELETE'
    }

    if ($draft) {
        $req.Uri = "/ltm/policy/~Common~Drafts~$name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Get-F5Monitor {
    param(
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri    = '/ltm/monitor'
        Method = 'GET'
    }

    # If we're only looking for a specific pool
    if ($name) {
        $req.Uri += "/$name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$name) {
        return $res.items
    }
    return $res
}

function New-F5Monitor {
    param(
        [string][Parameter(Mandatory = $true, ParameterSetName = 'Blank')][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $true, ParameterSetName = 'FromConfig')][ValidateNotNullOrEmpty()]
        $config_json,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = '/ltm/monitor'
        Method      = 'POST'
        Body        = "{ `"name`":`"$name`" }"
        ContentType = 'application/json'
    }

    if ($PSCmdlet.ParameterSetName -eq 'FromConfig') {
        $req.Body = $config_json
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Remove-F5Monitor {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri    = "/ltm/monitor/$name"
        Method = 'DELETE'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Get-F5DataGroup {
    param(
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [switch]
        $external
    )

    $req = @{
        Uri    = '/ltm/data-group'
        Method = 'GET'
    }

    if ($external) {
        $req.Uri += "/external"
    } else {
        $req.Uri += "/internal"
    }

    # If we're only looking for a specific data-group
    if ($name) {
        $req.Uri += "/$name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$name) {
        return $res.items
    }
    return $res
}

function New-F5DataGroup {
    param(
        [string][Parameter(Mandatory = $true, ParameterSetName = 'Blank')][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $true, ParameterSetName = 'FromConfig')][ValidateNotNullOrEmpty()]
        $config_json,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id,

        [switch]
        $external
    )

    $req = @{
        Uri         = '/ltm/data-group'
        Method      = 'POST'
        Body        = "{ `"name`":`"$name`", `"type`":`"ip`" }"
        ContentType = 'application/json'
    }

    if ($external) {
        $req.Uri += "/external"
    } else {
        $req.Uri += "/internal"
    }

    if ($PSCmdlet.ParameterSetName -eq 'FromConfig') {
        $req.Body = $config_json
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Edit-F5DataGroup {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $config_json,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id,

        [switch]
        $external
    )

    $req = @{
        Uri         = "/ltm/data-group/internal/$name"
        Method      = 'PATCH'
        Body        = $config_json
        ContentType = 'application/json'
    }

    if ($external) {
        $req.Uri = "/ltm/data-group/external/$name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Remove-F5DataGroup {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri    = "/ltm/data-group/internal/$name"
        Method = 'DELETE'
    }

    if ($external) {
        $req.Uri = "/ltm/data-group/external/$name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Get-F5AccessProfile {
    param(
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri    = '/apm/profile/access'
        Method = 'GET'
    }

    # If we're only looking for a specific Access Profile
    if ($name) {
        $req.Uri += "/$name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$name) {
        return $res.items
    }
    return $res
}

function Set-F5AccessProfile {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $config_json,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = '/apm/profile/access'
        Method      = 'POST'
        Body        = $config_json
        ContentType = 'application/json'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Get-F5AccessPolicy {
    param(
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri    = '/apm/policy/access-policy'
        Method = 'GET'
    }

    # If we're only looking for a specific access policy
    if ($name) {
        $req.Uri += "/$name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$name) {
        return $res.items
    }
    return $res
}

function Set-F5AccessPolicy {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $config_json,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = '/apm/policy/access-policy'
        Method      = 'POST'
        Body        = $config_json
        ContentType = 'application/json'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Get-F5AccessPolicyItem {
    param(
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri    = '/apm/policy/policy-item'
        Method = 'GET'
    }

    # If we're only looking for a specific policy item
    if ($name) {
        $req.Uri += "/$name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$name) {
        return $res.items
    }
    return $res
}

function New-F5AccessPolicyItem {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $config_json,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = '/apm/policy/policy-item'
        Method      = 'POST'
        Body        = $config_json
        ContentType = 'application/json'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Get-F5AccessPolicyAgent {
    param(
        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $name,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $type,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri    = '/apm/policy/agent'
        Method = 'GET'
    }

    if ($type) {
        $req.Uri += "/$type"
    }

    # If we're only looking for a specific policy agent
    if ($name) {
        $req.Uri += "/$name"
    }

    $res = Invoke-F5RestMethod $req $f5_connection

    if (!$name) {
        return $res.items
    }
    return $res
}

function New-F5AccessPolicyAgent {
    param(
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $type,

        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $config_json,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $transaction_id
    )

    $req = @{
        Uri         = "/apm/policy/agent/$type"
        Method      = 'POST'
        Body        = $config_json
        ContentType = 'application/json'
    }

    $res = Invoke-F5RestMethod $req $f5_connection $transaction_id

    return $res
}

function Publish-F5AccessPolicy {
    param (
        [string][Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        $path,

        [string][Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        $f5_connection
    )

    $req = @{
        Uri    = "/apm/profile/access/$($path -replace '/', '~')"
        Method = 'PATCH'
        Body   = '{ "generationAction":"increment" }'
    }

    $res = Invoke-F5RestMethod $req $f5_connection
    return $res
}
