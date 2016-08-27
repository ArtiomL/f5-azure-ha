# <img align="center" src="azure.png" height="70">&nbsp;&nbsp;F5 High Availability in Microsoft Azure
[![Releases](https://img.shields.io/github/release/ArtiomL/f5-azure-ha.svg)](https://github.com/ArtiomL/f5-azure-ha/releases)
[![Commits](https://img.shields.io/github/commits-since/ArtiomL/f5-azure-ha/v0.9.7.svg?label=commits%20since)](https://github.com/ArtiomL/f5-azure-ha/commits/master)
[![Maintenance](https://img.shields.io/maintenance/yes/2016.svg)](https://github.com/ArtiomL/f5-azure-ha/graphs/code-frequency)
[![Issues](https://img.shields.io/github/issues/ArtiomL/f5-azure-ha.svg)](https://github.com/ArtiomL/sublime-f5-irules/issues)
![TMOS](https://img.shields.io/badge/tmos-12.1-ff0000.svg)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](/LICENSE)
<br>
## Description

In a regular F5 Device Service Clustering working in High Availability mode, cluster members use Gratuitous ARP or MAC Masquerade during normal operation and when cluster failover occurs.

In Azure this is implemented by making RESTful API calls to Azure Resource Manager.

However, this isn't currently supported by F5:
> The two BIG-IP VEs are synchronizing their configurations to one another; they are not communicating for the purpose of failover. The BIG-IP VE high availability feature does not work in Azure, and you cannot create an active-standby pair.

 ([Source](https://support.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip-ve-setup-msft-azure-12-0-0/3.html))

<br>
## Installation
### [azure_ad_app.ps1](azure_ad_app.ps1)

To be able to make API calls automatically, the two HA members must be provided with Azure Active Directory credentials ([azure_ha.json](azure_ha.json)) using the Azure Role-Based Access Control (RBAC).

This PowerShell code ([azure_ad_app.ps1](azure_ad_app.ps1)) automates this **one-time** process, while some user input is still required:

```powershell
# Login to Azure RM
Login-AzureRmAccount

# Show all subscriptions
Get-AzureRmSubscription

# Select the subscription where the AD resides
$adSub = Get-AzureRmSubscription -SubscriptionName "Paper Street Soap"
$adSub | Select-AzureRmSubscription

# Record IDs
$subsID = $adSub.SubscriptionId
$tenantID = $adSub.TenantId

# AD application password
$adaPass = Read-Host 'Azure AD App Password:' -AsSecureString
$adaPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($adaPass))

# Create a new AAD application
$armADApp = New-AzureRmADApplication -DisplayName "adappREST" -HomePage "https://paperstsoap.com/adapprest" -IdentifierUris "https://paperstsoap.com/adapprest" -Password $adaPass

# Record the application ID
$appID = $armADApp.ApplicationId.Guid

# Create a new SPN
New-AzureRmADServicePrincipal -ApplicationId $appID

# Assign a new role
New-AzureRmRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $appID

# Show all resource groups
Get-AzureRmResourceGroup

# Select the resource group where the Azure Load Balancer (LBAZ), F5 VMs and their availability set reside
$rgName = "rgPAPERSTSOAP"

# Record F5 VMs' NICs
$nicF5A = ((Get-AzureRmVM -ResourceGroupName $rgName -Name ((Get-AzureRmAvailabilitySet -ResourceGroupName $rgName).VirtualMachinesReferences[0].Id -split 'virtualMachines/')[1]).NetworkInterfaceIDs -split 'networkInterfaces/')[1]
$nicF5B = ((Get-AzureRmVM -ResourceGroupName $rgName -Name ((Get-AzureRmAvailabilitySet -ResourceGroupName $rgName).VirtualMachinesReferences[1].Id -split 'virtualMachines/')[1]).NetworkInterfaceIDs -split 'networkInterfaces/')[1]

# Encode the password
$adaPass = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($adaPass))

# JSON values
@{ "subID" = $subsID; "tenantID" = $tenantID; "appID" = $appID; "pass" = $adaPass; "rgName" = $rgName; "nicF5A" = $nicF5A; "nicF5B" = $nicF5B } | ConvertTo-Json
```

<br>
This will result in a [`JSON`](azure_ha.json) file, similar to the following:
```json
{
	"appID": "a3e3cf25-2db0-432e-a122-8224cd46215a",
	"nicF5A": "vmf5a402",
	"nicF5B": "vmf5b513",
	"pass": "U2ViYXN0aWFu",
	"rgName": "rgPAPERSTSOAP",
	"subID": "b3481899-362a-4121-9355-1c4fa3e14b3d",
	"tenantID": "6a0a327e-6612-424d-bb4d-5420ca02b9a7"
}
```

<br>
This file should be placed at the following location on both HA BIG-IPs: `/shared/tmp/scripts/azure/azure_ha.json`
Alternatively, this path is controlled by the `-c` command line argument or the `strCFile` attribute of the `clsAREA` class (in [azure_ha.py](azure_ha.py)):
```python
# Azure RM REST API
class clsAREA(object):
	def __init__(self):
		self.strCFile = '/shared/tmp/scripts/azure/azure_ha.json'
```

<br>
### [azure_ha.py](azure_ha.py)

This is the actual HA / failover logic.

<br>
## Logging
All logging is **disabled** by default. Please use the `-l {0,1,2,3}` argument to set the required verbosity.<br>
Alternatively, this is controlled by the global `intLogLevel` variable:
```python
# Log level to /var/log/ltm (or stdout)
intLogLevel = 0
```
If run interactively, **_stdout_** is used for log messages (`python intLogLevel = 0`), otherwise `/var/log/ltm` will be used.

<br>
## --help
```
./azure_ha.py --help
usage: azure_ha.py [-h] [-a] [-c CFILE] [-f] [-l {0,1,2,3}] [-s] [-v]
                   [IP] [PORT]

F5 High Availability in Microsoft Azure

positional arguments:
  IP            peer IP address (required in monitor mode)
  PORT          peer HTTPS port (default: 443)

optional arguments:
  -h, --help    show this help message and exit
  -a            test Azure RM authentication and exit
  -c CFILE      config file location
  -f            force failover
  -l {0,1,2,3}  set log level (default: 0)
  -s            check current HA state and exit
  -v            show program's version number and exit

https://github.com/ArtiomL/f5-azure-ha
```
