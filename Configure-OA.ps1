
##############################################################################
## (C) Copyright 2013-2017 Hewlett Packard Enterprise Development LP 
##############################################################################
<#

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

#>

<#
 Note: This library requires the following installed:
 Microsoft .NET Framework 4.6: http://go.microsoft.com/fwlink/?LinkId=528259
 Windows Management Framework (aka PowerShell) 4: https://www.microsoft.com/en-us/download/details.aspx?id=40855
#>
## Input parameters:
##         OAApplianceIP                      = IP address of the OV appliance
##		   OAAdminName                        = Administrator name of the appliance
##         OAAdminPassword                    = Administrator's password
##         OAEBIPACSV                         = path to the CSV file containing Enclosure Bay and Interconnect networks definition
##         OASNMPCSV                          = path to the CSV file containing SNMP definition
##         OASNMPUserCSV                      = path to the CSV file containing SNMP User definition
##         OASNMPTrapCSV                      = path to the CSV file containing SNMP trap definition
##         OALDAPCSV                          = path to the CSV file containing LDAP definition
##         OAAlertMailCSV                     = path to the CSV file containing OAALertMail definition
##
##
## History: 
##         May 2017 : v1.0
##
## -------------------------------------------------------------------------------------------------------------
<#
  .SYNOPSIS
     Configure OA settings
  
  .DESCRIPTION
	 Configure OA settings
        
  .EXAMPLE

    .\ Configure-OA.ps1  -OAApplianceIP 10.254.1.66 -OAAdminName Administrator -password P@ssword1 -OAEBIPA.CSV .\net.csv 
        The script connects to OA and configure OA sertings


  .PARAMETER OAApplianceIP                   
    IP address of the OA 

  .PARAMETER OAAdminName                     
    Administrator name of the appliance

  .PARAMETER OAAdminPassword                 
    Administrator s password
    
  .PARAMETER OAEBIPACSV
    Path to the CSV file containing networks definition
 
   .PARAMETER OASnmpCSV
    Path to the CSV file containing SNMP definition

   .PARAMETER OASnmpUserCSV
    Path to the CSV file containing SNMPv3 users

    .PARAMETER OASnmpTrapCSV
    Path to the CSV file containing Trap definition

    .PARAMETER OALDAPCSV
    Path to the CSV file containing LDAP definition

    .PARAMETER OAAlertMailCSV
    Path to the CSV file containing Alert Mail definition

  .Notes
    NAME:     Configure-OA
    LASTEDIT: 05/15/2017
   
  .Link
     Http://www.hpe.com
 
 #Requires PS -Version 3.0
 #>
  
## -------------------------------------------------------------------------------------------------------------


Param ( [string]$OAApplianceIP="", 
        [string]$OAAdminName="", 
        [string]$OAAdminPassword="HPinvent_1",
                                             
        [string]$OAEBIPACSV    = "",
        [string]$OASnmpCSV     = "",
        [string]$OASnmpUserCSV = "",
        [string]$OASnmpTrapCSV = "",
        [string]$OALDAPCSV     = "",
        [string]$OAALertMailCSV = ""

     )

$DoubleQuote = '"'
$BackSlash   = '\'
$SepChar     = '|'


$EnableValues   = @('Enable','Disable')
$OnOffValues    = @('On','Off')
$PriSecValues   = @('Primary','Secondary')
$RWValues       = @('Read','Write')

$OAModule =  "C:\Program Files\Hewlett-Packard\PowerShell\Modules\HPOACmdlets" 

## -------------------------------------------------------------------------------------------------------------
##
##                     Function Create-OAEBIPA
##
## -------------------------------------------------------------------------------------------------------------

Function Create-OAEBIPA
{


Param ([string]$OAEBIPACSV ="")

    if ( -not (Test-path $OAEBIPACSV ))
    {
        write-host "No file specified or file $OAEBIPACSV  does not exist."
        return
    }
    # Read the CSV Users file
    $tempFile = [IO.Path]::GetTempFileName()
    type $OAEBIPACSV  | where { ($_ -notlike ",,,,,*") -and ($_ -notlike '"*') -and ( $_ -notlike "#*") -and ($_ -notlike ",,,#*") } > $tempfile   # Skip blank line
    
    $DNS     = @()
    $NTPRole = ""
    $NTPIP   = ""

    $ListofNets    = import-csv $tempfile | Sort Target

    foreach ($N in $ListofNets)
    {
        $Target         = $N.Target
        $Bay            = $N.Bay
        $State          = $N.State 
            if ($State -eq "")
                { $State = 'Disable' }

        $IP             = $N.IPAddress
        $Netmask        = $N.Netmask
        $GW             = $N.Gateway
        $Domain         = $N.Domain
        $DNS            = if ($N.DNS) { $N.DNS.Split($SepChar) }         else {$NULL}

        $NTPRole        = if ($N.NTPRole) { $N.NTPRole.Split($Sepchar) } else {@('Primary', 'Secondary')}
        $NTPIP          = if ($N.NTPIP) { $N.NTPIP.Split($Sepchar)}      else {$NULL}

        if ($Bay)
        {
            $EBIPACmd = "Set-HPOAEBIPA -Connection `$Global:ThisConnection -Target $Target -Bay `$Bay -force "

            $Statecmd = " -State $State "


            $IPcmd = " " 
            if ($IP) 
                {$IPcmd = " -IP $IP " }                     

            $NetMaskcmd  = " " 
            if ($Netmask)                   
                {$NetMaskcmd = " -netmask $Netmask " }          

            $GWcmd = " "
            if ($GW)
                { $GWcmd = " -gateway $GW " }

            $Domaincmd = " "
            if ($Domain)
                { $Domaincmd = " -Domain $Domain " }


            write-host -foreground Cyan "-------------------------------------------------------------"
            write-host -foreground Cyan "Configuring $Target on bay $Bay...."
            write-host -foreground Cyan "-------------------------------------------------------------"
            
            write-host -foreground Cyan "`t Configuring Bay $Bay with IP Address $IP ....."

            $EBIPACmd +=  $Statecmd + $IPcmd + $NetMaskcmd + $GWcmd + $Domaincmd 

            # Target is Interconnect
            if ($Target -eq 'InterConnect' -and $NTPIP) 
            {
                for ($i=0; $i -lt $NTPIP.Length; $i++)
                {
                    $ICcmd     = " -NTP " + $NTPRole[$i] + " -NTPIP " + $NTPIP[$i] 
                    $EB_ICcmd  = $EBIPACmd + $ICcmd
                    Invoke-Expression $EB_ICcmd
                }

            }
            else 
            {
                    
                    Invoke-Expression $EBIPACmd    
            }



            # -- Configure DNS

            foreach ($DNSIP in $DNS)
            {
                if ($DNSIP)
                {
                    $DNSIP = $DNSIP.Trim()
                     write-host -foreground Cyan "`t Configuring DNS server for bay $Bay with IP Address $DNSIP....."
                    $res = Add-HPOAEBIPA -Connection $Global:ThisConnection -Target $Target -IP $DNSIP -Bay $Bay
                }
            }
        }
        else
        {
         write-host -ForegroundColor Yellow "Bay not specified. Skip creating it..."
        }

    }
    write-host -ForegroundColor CYAN "Saving configuration to flash memory..."
    Save-HPOAEBIPA -force -Connection  $Global:ThisConnection
}



## -------------------------------------------------------------------------------------------------------------
##
##                     Function Create-OASnmp
##
## -------------------------------------------------------------------------------------------------------------

Function Create-OASnmp
{


Param ([string]$OASnmpCSV ="")

    if ( -not (Test-path $OASnmpCSV ))
    {
        write-host "No file specified or file $OASnmpCSV  does not exist."
        return
    }
    # Read the CSV Users file
    $tempFile = [IO.Path]::GetTempFileName()
    type $OASnmpCSV  | where { ($_ -notlike ",,,,,*") -and ($_ -notlike '"*') -and ( $_ -notlike "#*") -and ($_ -notlike ",,,#*") } > $tempfile   # Skip blank line
        

    $ListofSnmp    = import-csv $tempfile
  
    foreach ($S in $ListofSnmp)
    {
        $State              = $S.State
        $Type               = $S.Type
        $CommunityName      = $S.CommunityName
        $Contact            = $s.Contact
        $EngineId           = $S.EngineId
        $Location           = $S.Location
    
        $Validation = ($Contact.Length -lt 20) -and ($Community.Length -lt 20) -and ($Location.Length -lt 20) -and ($EngineId.Length -lt 27)   

        if ($Validation)                    
        {
            write-host -foreground Cyan "-------------------------------------------------------------"
            write-host -foreground Cyan "Configuring SNMP settings for OA....                         "
            write-host -foreground Cyan "-------------------------------------------------------------"
            
            write-host -foreground Cyan "`t Using Access Type $Type                                   "
            write-host -foreground Cyan "`t Using Community Name $CommunityName                       "
            write-host -foreground Cyan "`t Using Contact name $Contact                               "
            write-host -foreground Cyan "`t Using Location $Location                                  "


            $State = if ( $EnableValues -contains $State) {$State} else {'Enable' }
            $Type  = if ( $RWValues -contains $Type)      {$Type } else { 'Read'}
             
            Set-HPOASNMP -State $State -Type $Type -CommunityName $CommunityName -Contact $Contact -EngineId $EngineId -Location $Location -Connection $global:ThisConnection -force
        }
        else            
        {
            write-host -ForegroundColor Yellow "Contact string must be between 0 and 20 characters --> $Contact..."
            write-host -ForegroundColor Yellow "Review the Contact name and re-run the script..."
        }
    
    }
}

## -------------------------------------------------------------------------------------------------------------
##
##                     Function Create-OASnmpUser
##
## -------------------------------------------------------------------------------------------------------------

Function Create-OASnmpUser
{


Param ([string]$OASnmpUserCSV ="")

    if ( -not (Test-path $OASnmpUserCSV ))
    {
        write-host "No file specified or file $OASnmpUserCSV  does not exist."
        return
    }
    # Read the CSV Users file
    $tempFile = [IO.Path]::GetTempFileName()
    type $OASnmpUserCSV  | where { ($_ -notlike ",,,,,*") -and ($_ -notlike '"*') -and ( $_ -notlike "#*") -and ($_ -notlike ",,,#*") } > $tempfile   # Skip blank line
        

    $ListofSnmpUsers    = import-csv $tempfile
  
    foreach ($U in $ListofSnmpUsers)
    {
        $Username                   = $U.Username.Trim()
        $AuthPassphraseEncoding     = $U.AuthPassphraseEncoding.Trim()
        $AuthPassphrase             = $U.AuthPassphrase.Trim()
        $PrivacyPassphraseEncoding  = $U.PrivacyPassphraseEncoding.Trim()
        $PrivacyPassphrase          = $U.PrivacyPassphrase.Trim()
        $SecurityLevel              = $U.SecurityLevel.Trim()
        $EngineId                   = $U.EngineId.Trim()
        $RWAccess                   = $U.ReadWriteAccess.Trim() -eq 'Yes'
       

 

        if ($Username)                    
        {
            $Result = Get-HPOASNMPUser -User $Username -Connection $Global:ThisConnection -force
            if ($Result.StatusType -eq "Error")   ## USer doees not exist
            {
                write-host -foreground Cyan "-------------------------------------------------------------"
                write-host -foreground Cyan "Configuring SNMPv3 User $Username for OA....                         "
                write-host -foreground Cyan "-------------------------------------------------------------"

                Add-HPOASNMPUser -Username $Username -AuthPassphraseEncoding $AuthPassphraseEncoding -AuthPassphrase $AuthPassphrase -PrivacyPassphraseEncoding $PrivacyPassphraseEncoding -PrivacyPassphrase $PrivacyPassphrase -SecurityLevel $SecurityLevel -EngineId $EngineId -ReadWriteAccess:$RWAccess -Connection $global:ThisConnection -force | FL
            }
            else            
            {
                write-host -ForegroundColor Yellow "This SNMPv3 User --> $username already exists..."
            
            }
        }
        else            
        {
            write-host -ForegroundColor Yellow "USername not specified. Skip creating user...."
            
        }
    
    }
}



## -------------------------------------------------------------------------------------------------------------
##
##                     Function Create-OASnmpTrap
##
## -------------------------------------------------------------------------------------------------------------

Function Create-OASnmpTrap
{


Param ([string]$OASnmpTrapCSV ="")

    if ( -not (Test-path $OASnmpTRapCSV ))
    {
        write-host "No file specified or file $OASnmpTrapCSV  does not exist."
        return
    }
    # Read the CSV  file
    $tempFile = [IO.Path]::GetTempFileName()
    type $OASnmpTrapCSV  | where { ($_ -notlike ",,,,,*") -and ($_ -notlike '"*') -and ( $_ -notlike "#*") -and ($_ -notlike ",,,#*") } > $tempfile   # Skip blank line
        

    $ListofSnmpTraps    = import-csv $tempfile
  
    foreach ($T in $ListofSnmpTraps)
    {
        $Hostname                   = $T.Hostname.Trim()
        $Username                   = $T.Username.Trim()
        $CommunityName              = $T.CommunityName.Trim()

        $SNMPv3                     = $T.SNMPv3.Trim() -eq 'Yes'
        $Privilege                  = $T.Privilege
        $InformEvent                = $T.InformEvent.Trim() -eq 'Yes'

       
        $SnmpSettings  = Get-HPOASNMP -Connection $global:ThisConnection
        if ($SnmpSettings.StatusType -eq 'OK')
        {

            if ($Username)                    
            {
                $ThisUser = Get-HPOASNMPUser -User $Username -Connection $Global:ThisConnection -force
             
                if (($ThisUser.StatusType -eq 'OK' ) -and ($HostName))  ## USer exists
                {

                    $EngineId = $ThisUser.EngineId
                    $TrapReceiverHost = $SnmpSettings.TrapReceiverHost -join $SepChar
                    
                    
                    write-host -foreground Cyan "-------------------------------------------------------------"
                    write-host -foreground Cyan "Configuring SNMPv3 Trap for OA....                           "
                    write-host -foreground Cyan "-------------------------------------------------------------"

                    $EngineId  = $ThisUser.EngineId
                    
                    if ($SNMPv3)
                    {
                        
                        $AlreadyConfigv3    = $TrapReceiverHost -like "*$HostName*$UserName*$EngineId*" 
                        if (-not $AlreadyConfigv3)
                        {
                            write-host -foreground Cyan "`t Configuring Receiver Host $HostName "
                            write-host -foreground Cyan "`t Configuring SnmpUser $UserName "
                            write-host -foreground Cyan "`t Access type $Privilege "

                            Add-HPOASNMPTrapReceiver -Username $Username -Host $HostName  -SNMPv3:$SNMPv3 -Privilege $Privilege -InformEvent:$InformEvent -EngineId $EngineId  -Connection $global:ThisConnection -force | FL
                        }
                        else            
                        {
                            write-host -ForegroundColor Yellow "Host $HostName and User $Username are already listed as a Trap Receiver. Skip creating Trap Receiver....."
            
                        }
                    }
                    else
                    {
                        $AlreadyConfigv1    = $TrapReceiverHost -like "*$HostName*$CommunityName*" 
                        if (-not $AlreadyConfigv1)
                        {
                            write-host -foreground Cyan "`t Configuring Receiver Host $HostName "
                            write-host -foreground Cyan "`t Configuring Community $CommunityName "

                            Add-HPOASNMPTrapReceiver -Host $HostName -CommunityName $CommunityName  -InformEvent:$InformEvent  -Connection $global:ThisConnection -force | FL
                        }
                        else            
                        {
                            write-host -ForegroundColor Yellow "Host $HostName and Community $CommunityName are already listed as a Trap Receiver. Skip creating Trap Receiver....."
            
                        }
                    }

                }
                else            
                {
                    write-host -ForegroundColor Yellow "Either User --> $username does not exist or host name is empty. Skip creating Trap Receiver....."
            
                }
            }
            else            
            {
                write-host -ForegroundColor Yellow "USername not specified. Skip creating SNMP Trap Receiver...."
            
            }
        }
       
        else
        {
             write-host -ForegroundColor Yellow "SNMP is not configured. Skip creating SNMP traps....."
             return
        }
    
    }
}

## -------------------------------------------------------------------------------------------------------------
##
##                     Function Create-OALDAP
##
## -------------------------------------------------------------------------------------------------------------

Function Create-OALDAP
{
Param ([string]$OALdapCSV ="")

    if ( -not (Test-path $OALdapCSV ))
    {
        write-host "No file specified or file $OALdapCSV  does not exist."
        return
    }
    # Read the CSV  file
    $tempFile = [IO.Path]::GetTempFileName()
    type $OALdapCSV  | where { ($_ -notlike ",,,,,,,,,*") -and ($_ -notlike '"*') -and ( $_ -notlike "#*") -and ($_ -notlike ",,,#*") } > $tempfile   # Skip blank line
        

    $ListofLdaps    = import-csv $tempfile


    foreach ($L in $ListofLdaps)
    {
        $LDAPState                    = $L.LDAPState
        $LocalUserState               = $L.LocalUserState  
                        
        $Servername                   = $L.Servername.Trim()
        $Port                         = $L.Port.Trim()
        $GCPort                       = $L.GCPort.Trim()

        $SearchContext                = $L.SearchContext.Trim()
        $SearchPriority               = $L.SearchPriority.Trim()

        $NameMapping                  = $L.NameMapping.Trim()
        $LDAPGroup                    = $L.LDAPGroup.Trim()
        $Description                  = if ($L.Description) {$L.Description.Trim() } else { "   "}
        $Access                       = $L.Access.Trim()

        $Target                       = $L.Target
        $Bay                          = $L.Bay

        $OABaysAccess                 = $L.OABaysAccess -eq 'Yes'


        # ----- Configure LDAP settings
        #

                            
        write-host -foreground Cyan "-------------------------------------------------------------"
        write-host -foreground Cyan "Configuring LDAP Settings for OA....                         "
        write-host -foreground Cyan "-------------------------------------------------------------"


        # ------- LDAP Server
        
        write-host -foreground Cyan "`t Configuring LDAP Server and Ports ....                         "
        
        if ($Servername)
            { Set-HPOALDAPSetting -Server $ServerName -connection $Global:ThisConnection -force    }
        if ($Port)
            { Set-HPOALDAPSetting -Port $Port -connection $Global:ThisConnection -force     }
        if ($GCPort)
            { Set-HPOALDAPSetting -GCPort $GCPort -connection $Global:ThisConnection -force    }

        #--- SearchContext Settings
        # --- Up to 6 entries

       write-host -foreground Cyan "`t Configuring Search Context ....                         "
        
        if ($SearchContext -and $SearchPriority)
        {
            $Context  = $SearchContext.Split($SepChar)
            $Priority = $SearchPriority.Split($SepChar)
            for ($i=0;$i -lt $Context.Length; $i++)
            {
                Set-HPOALDAPSetting -SearchContent $Context[$i] -SearchPriority $Priority[$i] -connection $Global:ThisConnection -force  
            }
        }

        # ------- LDAP Group

        write-host -foreground Cyan "`t Configuring LDAP Group ....                         "
        

        if ($LDAPGroup)
        {
            $result = Get-HPOALDAPGroup -connection $Global:ThisConnection
            if ($result.StatusMessage -eq 'No LDAP groups were detected')
            {
                Add-HPOALDAPGroup -Group $LDAPGroup -connection $Global:ThisConnection -Force
            }
            else  # Check for GroupName
            {
                $GrpNames = $result.LDAPGroupList.LDAPGroup -join $sepChar
                if ($GrpNames -notlike "*$LDAPGroup*") 
                {
                    Add-HPOALDAPGroup -Group $LDAPGroup -connection $Global:ThisConnection -Force
                }

            }


            Set-HPOALDAPSetting -Group $LDAPGroup -Access $Access -Description $Description -connection $Global:ThisConnection -force    
        }
        
        # ------- NameMapping
 
         write-host -foreground Cyan "`t Configuring NT Name Mapping ....                         "
 
 
        if ($OnOffValues -contains $NameMapping)
        {
            Set-HPOALDAPSetting -NameMapping $NameMapping -connection $Global:ThisConnection -force  
        }

        # ---- Bay and Interconnect Access

        write-host -foreground Cyan "`t Configuring Access to bays and Interconnect ....                         "
 
        if ($Bay -and $Target -and $LDAPGroup)
        {
            $Bays = $Bay.Split($SepChar)
            foreach ($B in $Bays)
            {
                Add-HPOALDAPBay  -Target $Target -Bay $B -Group $LDAPGroup -connection $Global:ThisConnection -force 
            }
        } 

        # ----- OA Bay Access
 
        write-host -foreground Cyan "`t Configuring Access to OA bay ....                         "
 
        if ($OABaysAccess)
        {
            Add-HPOALDAPPrivilege -Group $LDAPGroup -connection $Global:ThisConnection -force 
        }

        # ---- Enable LDAP 

        write-host -foreground Cyan "`t Enabling LDAP  ....                         "
 
        if (($EnableValues -contains $LDAPState) -and  ($EnableValues -contains $LocalUserState))
        {
            Set-HPOALDAP -State $LDAPState -Connection $Global:ThisConnection -force    
        }




    }

}


## -------------------------------------------------------------------------------------------------------------
##
##                     Function Create-OAAlertMail
##
## -------------------------------------------------------------------------------------------------------------

Function Create-OAAlertMail
{
Param ([string]$OAAlertMailCSV ="")

    if ( -not (Test-path $OAAlertMailCSV ))
    {
        write-host "No file specified or file $OAAlertMailCSV  does not exist."
        return
    }
    # Read the CSV  file
    $tempFile = [IO.Path]::GetTempFileName()
    type $OAAlertMailCSV  | where { ($_ -notlike ",,,,,,,,,*") -and ($_ -notlike '"*') -and ( $_ -notlike "#*") -and ($_ -notlike ",,,#*") } > $tempfile   # Skip blank line
        

    $ListofAlertMails    = import-csv $tempfile


    foreach ($M in $ListofAlertMails)
    {
        $AlertMailState                    = $M.AlertMailState
        $EMail                             = $M.EMail
        $Domain                            = $M.Domain
        $SMTPServer                        = $M.SMTPServer

        $AlertCmd = " "
        $AlertMailState = if ($EnableValues -contains $AlertMailState) {$AlertMailState} else {'Disable'}
        $AlertCmd = " -State $AlertMailState " 
        
        $EmailCmd = " "
        if ($Email)
        { $EmailCmd = " -EMail $Email " }

        $DomainCmd = " "
        if ($Domain)
        { $DomainCmd = " -Domain $Domain " }

        $SMTPCmd = " "
        if ($SMTPServer)
        { $SMTPCmd = " -SMTPServer $SMTPServer " }

        $AlertMailCmd = " Set-HPOAAlertmail -Connection `$Global:ThisConnection -force " +  $AlertCmd + $EmailCmd + $DomainCmd + $SMTPCmd 

                          
        write-host -foreground Cyan "-------------------------------------------------------------"
        write-host -foreground Cyan "Configuring Alert Mail for OA....                            "
        write-host -foreground Cyan "-------------------------------------------------------------"

        write-host -foreground Cyan "`t Using e-mail address $Email                                "
        write-host -foreground Cyan "`t Using Sender Domain $Domain                                "
        write-host -foreground Cyan "`t Using SMTP Server  $SMTPServer                             "

        invoke-Expression $AlertMailCmd
        
    }
}

# -------------------------------------------------------------------------------------------------------------
#
#                  Main Entry
#
#
# -------------------------------------------------------------------------------------------------------------


       
       # -----------------------------------
       #    Always reload module
   
       $ModuleName = $OAModule.Split($BackSlash)[-1]

       $LoadedModule = get-module -name $ModuleName

       if ($LoadedModule)
       {
            remove-module $LoadedModule
       }

       import-module $OAModule
       

        # ---------------- Connect to OA
        #
        write-host "`n Connect to  OA --> $OAApplianceIP ..."
        $Global:ThisConnection = Connect-HPOA -OA $OAApplianceIP -username $OAAdminName -password $OAAdminPassword

        if ( ! [string]::IsNullOrEmpty($OAEBIPACSV) -and (Test-path $OAEBIPACSV) )
        {
            Create-OAEBIPA -OAEBIPACSV $OAEBIPACSV 
        }

        if ( ! [string]::IsNullOrEmpty($OASnmpCSV) -and (Test-path $OASnmpCSV) )
        {
            Create-OASnmp -OASnmpCSV $OASnmpCSV 
        }

        if ( ! [string]::IsNullOrEmpty($OASnmpUserCSV) -and (Test-path $OASnmpUserCSV) )
        {
            Create-OASnmpUser -OASnmpUserCSV $OASnmpUserCSV 
        }

    
        if ( ! [string]::IsNullOrEmpty($OASnmpTrapCSV) -and (Test-path $OASnmpTrapCSV) )
        {
            Create-OASnmpTrap -OASnmpTrapCSV $OASnmpTrapCSV 
        }

        if ( ! [string]::IsNullOrEmpty($OALDAPCSV) -and (Test-path $OALDAPCSV) )
        {
            Create-OALDAP -OALDAPCSV $OALDAPCSV 
        }

        if ( ! [string]::IsNullOrEmpty($OAAlertMailCSV) -and (Test-path $OAAlertMailCSV) )
        {
            Create-OAAlertMail -OAAlertMailCSV $OAAlertMailCSV 
        }