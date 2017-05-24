# Configure-OA PowerShell script
Configure-OA.PS1 is a PowerShell script that leverages HPE OA Cmdlets to automate configuration of OA settngs including
    - Alert Mail
    - Enclosure Bay IP Addreesing (EBIPA)
    - LDAP AUthentication
    - SNMP settings / SNMP Users / SNMP Traps

Settings are configured using Excel spreadsheets. Each tab in the sheet is saved as CSV file and the PowerShell script will use CSV files to read settings and configure OA
