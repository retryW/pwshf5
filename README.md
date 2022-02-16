# PWSHF5
PWSHF5 is a PowerShell Core module for interacting with the F5 network interface iControlREST api.

**Usage**

Note: it is highly advised to always assign a PWSHF5 function call to a variable to ensure you can interact with the returned object after the function is called.

1. Install the Module
```powershell
Install-Module PWSHF5
```

2. Import the Module
```powershell
Import-Module PWSHF5
```

3. Usage
```powershell
# Setup environment
Set-F5Connection -name 'dev_f5' -url 'https://1.2.3.4' -credential (Get-Credential)

# Get a list of all irules
Get-F5iRule

# Get a specific irule
$irule = Get-F5iRule -name 'irule_cale_test_from_api'

# 1. Create an submit a full transaction (transactions should be used on almost all create/edit actions, particularly ones involving more than one component)
$tx = New-F5Transaction

# 2. Create some F5 objects
$irule = New-F5iRule -name 'my_new_irule' -transaction_id $tx
$vs    = New-F5VirtualServer -config_json $some_config_as_json -transaction_id $tx

# 3. Submit the transactions (an exception is thrown on failure)
Submit-F5Transaction -id $tx
```
