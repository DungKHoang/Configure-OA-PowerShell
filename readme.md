# Configure OA with PowerShell

Configure-OA.PS1 is a PowerShell script that leverages HPE OA Cmdlets to automate configuration of OA settngs including
* Alert Mail
* Enclosure Bay IP Addreesing (EBIPA)
* LDAP AUthentication
* SNMP settings / SNMP Users / SNMP Traps

## Prerequisites
The script requires the follwoing PowerShell libraries:
* OneView PowerShell library : https://github.com/HewlettPackard/POSH-HPOneView/releases
* OA cmdlets                 : http://h20566.www2.hpe.com/hpsc/swd/public/detail?sp4ts.oid=1008862655&swItemId=MTX_faf40660fdd346ae9548b86b57&swEnvOid=4210


## Excel spreadsheet

Settings are configured using Excel spreadsheets. 
Each tab in the sheet is saved as CSV file and the PowerShell script will use CSV files to read settings and configure OA

## Syntax

### To configure Alert Mail

```
    .\Configure-OA.ps1 -OAApplianceIP <OA-IP-Address> -OAAdminName <Admin-name> -OAAdminPassword <password> -OAAlertMailCSV c:\AlertMail.csv

```

### To configure EBIPA

```
    .\Configure-OA.ps1 -OAApplianceIP <OA-IP-Address> -OAAdminName <Admin-name> -OAAdminPassword <password> -OAEBIPACSV c:\EBIPA.csv

```

### To configure LDAP Authentication

```
    .\Configure-OA.ps1 -OAApplianceIP <OA-IP-Address> -OAAdminName <Admin-name> -OAAdminPassword <password> -OALDapCSV c:\LDap.csv

```

### To configure SNMP settings

```
    .\Configure-OA.ps1 -OAApplianceIP <OA-IP-Address> -OAAdminName <Admin-name> -OAAdminPassword <password> -OASNMPCSV c:\SNMP.csv

```


### To configure SNMP User

```
    .\Configure-OA.ps1 -OAApplianceIP <OA-IP-Address> -OAAdminName <Admin-name> -OAAdminPassword <password> -OASNMPUserCSV c:\SNMPUsers.csv

```


### To configure SNMP Trap

```
    .\Configure-OA.ps1 -OAApplianceIP <OA-IP-Address> -OAAdminName <Admin-name> -OAAdminPassword <password> -OASNMPTrapCSV c:\SNMPTrap.csv

```
