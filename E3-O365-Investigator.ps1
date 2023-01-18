$ErrorActionPreference = "SilentlyContinue"
Install-Module ExchangeOnlineManagement
Connect-ExchangeOnline
$Global:QualityKillSwitch = $false
$Company1 = (Read-Host "what is the name of the company?") -replace " ",""
$Suspect = Read-Host "what email address are we investigating?"
$Dater = Get-Date -Format "MM-dd-yyyy-HHmmss"
$Foldername = ($Suspect -split "@")[0]
$Foldername = "$Company1-$Foldername-$Dater"
New-Item -ItemType Directory -Force -Path "C:\temp\$FolderName" | out-null
Write-Progress -Activity "Pulling logs down..." -Status "This may take awhile, please wait..."
$logs = Search-UnifiedAuditLog -ResultSize 5000 -StartDate (Get-Date).AddDays(-60) -EndDate (Get-Date) -UserIds $Suspect
$auditdata = $logs.auditdata | ConvertFrom-Json

function Compress-Array {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] $array
    )
    $Output =""
    $count = 0
    foreach($entry in $array){
        $count++
        if($entry.name){
            $Output += $entry.name
            $Output += ": "
            $Output += $entry.value
            if($count -lt $array.length) { $Output += "`n" }
        } elseif ($entry.ID) {
            $Output += $entry.ID
            $Output += ": "
            $Output += $entry.type
            if($count -lt $array.length) { $Output += "`n" }
        }
    }
    return $Output
}


function Get-IPAPIInfo {
    Param(
        [Parameter(Mandatory = $true)][string]$Ip
    )
    
    if ($null -ne ($ip -as [Version])) {
        $output = Get-IPData -Ip $IP -QualityScore
    } else {
        $output = Get-IPData -Ip $IP
    }
    return $output
}

function Get-IPData {
    Param(
        [Parameter(Mandatory = $true)][string]$Ip,
        [switch]$QualityScore
    )
    $ipResult = Invoke-restmethod -method get -uri "http://ip-api.com/json/$($ip)"
    if($QualityScore -and !$Global:QualityKillSwitch){
        $QualityCheck = (Invoke-webrequest -Uri "https://ipqualityscore.com/api/json/ip/qH5c9KP6m8iiiZsEvAZMOJS8WIDij2mA/$($ip)?strictness=1&allow_public_access_points=true&fast=true&lighter_penalties=true&mobile=true").content | ConvertFrom-Json
        if ($QualityCheck.success -eq $true) {
            $output = [PSCustomObject]@{
                Query = $ipResult.query
                Country = $ipResult.country
                'Country Code' = $QualityCheck.county_code
                Region = $QualityCheck.region
                City = $QualityCheck.city
                Zip = $QualityCheck.zip
                ISP = $QualityCheck.ISP
                ASN = $QualityCheck.ASN
                Organization = $QualityCheck.organization
                'Timezone' = $QualityCheck.timezone
                Latitude = $QualityCheck.latitude
                Longitude = $QualityCheck.longitude
                'IS Crawler' = $QualityCheck.is_crawler
                'Fraud Score' = $QualityCheck.fraud_score
                Mobile = $QualityCheck.mobile
                Proxy = $QualityCheck.proxy
                Vpn = $QualityCheck.vpn
                'Active VPN' = $QualityCheck.active_vpn
                Tor = $QualityCheck.tor
                'Active Tor' = $QualityCheck.active_tor
                'Recent Abuse' = $QualityCheck.recent_abuse
                'Bot Status' = $QualityCheck.bot_status
            } 
        } else {
            if(!$Global:QualityKillSwitch){
                $Global:QualityKillSwitch = $true
                write-host "API Limit has been reached"
            }
            $output = [PSCustomObject]@{
                Query = $ipResult.query
                Country = $ipResult.country
                'Country Code' = $ipResult.countyCode
                Region = $ipResult.region
                City = $ipResult.city
                Zip = $ipResult.zip
                ISP = $ipResult.isp
                ASN = $ipResult.as
                Organization = $ipResult.org
                'Timezone' = $ipResult.timezone
                Latitude = $ipResult.lat
                Longitude = $ipResult.lon
                'IS Crawler' = "API Limiter"
                'Fraud Score' = "API Limiter"
                Mobile = "API Limiter"
                Proxy = "API Limiter"
                Vpn = "API Limiter"
                'Active VPN' = "API Limiter"
                Tor = "API Limiter"
                'Active Tor' = "API Limiter"
                'Recent Abuse' = "API Limiter"
                'Bot Status' = "API Limiter"
            }
        }
    } else {
        $output = [PSCustomObject]@{
            Query = $ipResult.query
            Country = $ipResult.country
            'Country Code' = $ipResult.countyCode
            Region = $ipResult.region
            City = $ipResult.city
            Zip = $ipResult.zip
            ISP = $ipResult.isp
            ASN = $ipResult.as
            Organization = $ipResult.org
            'Timezone' = $ipResult.timezone
            Latitude = $ipResult.lat
            Longitude = $ipResult.lon
            'IS Crawler' = "IPv6"
            'Fraud Score' = "IPv6"
            Mobile = "IPv6"
            Proxy = "IPv6"
            Vpn = "IPv6"
            'Active VPN' = "IPv6"
            Tor = "IPv6"
            'Active Tor' = "IPv6"
            'Recent Abuse' = "IPv6"
            'Bot Status' = "IPv6"
        }
    }
    return $output
}
 
function Merge-IPAPIInfo {
    Param(
        [Parameter(Mandatory = $true)][string]$IpProperty,
        [Parameter(Mandatory = $true)][object]$Items
    )
    $ips = $items.$($IpProperty) | Sort-Object -Unique
    $ipResultCollection = @()
    $count = 0
    foreach($ip in $ips) {
        Write-Progress -Activity "IP Data Checks" -Status "Processing..." -PercentComplete (($count/$ips.length)*100)
        $originalQuery = $ip
        if ($ip) {
            if ($ip -match "\." -and $ip -match ":") {
                $ip = ($ip -split ":")[0]
            }
            if ($ip -match "\]:") {
                $ip = ($ip -split "\]:")[0]
                $ip = $ip -replace "\[", ""
            }
        }
        if ($ip -match "\]") {
            $ip = $ip -replace "\]", ""
            $ip = $ip -replace "\[", ""
        }
        if($ipResultCollection){
            if(!$ipResultCollection.query.Contains($ip)){
                $IPOutput = Get-IPAPIInfo -Ip $ip
                $IPOutput | add-member -NotePropertyName 'Original Query' -NotePropertyValue $originalQuery -Force
                $ipResultCollection += $IPOutput
                Start-Sleep -s 1
            }
            else{
                $IPResultCopy = $ipResultCollection.where({$_.query -eq $ip}, 'First')
                $IPOutput = [PSCustomObject]@{
                    Query = $ip
                    Country = $IPResultCopy.Country
                    'Country Code' = $IPResultCopy.'Country Code'
                    Region = $IPResultCopy.Region
                    City = $IPResultCopy.City
                    Zip = $IPResultCopy.Zip
                    ISP = $IPResultCopy.ISP
                    ASN = $IPResultCopy.ASN
                    Organization = $IPResultCopy.Organization
                    'Timezone' = $IPResultCopy.'Timezone'
                    Latitude = $IPResultCopy.Latitude
                    Longitude = $IPResultCopy.Longitude
                    'IS Crawler' = $IPResultCopy.'IS Crawler'
                    'Fraud Score' = $IPResultCopy.'Fraud Score'
                    Mobile = $IPResultCopy.Mobile
                    Proxy = $IPResultCopy.Proxy
                    Vpn = $IPResultCopy.Vpn
                    'Active VPN' = $IPResultCopy.'Active VPN'
                    Tor = $IPResultCopy.Tor
                    'Active Tor' = $IPResultCopy.'Active Tor'
                    'Recent Abuse' = $IPResultCopy.'Recent Abuse'
                    'Bot Status' = $IPResultCopy.'Bot Status'
                }
                $IPOutput | add-member -NotePropertyName 'Original Query' -NotePropertyValue $originalQuery -Force
                $ipResultCollection += $IPOutput
            }
        } else {
            $IPOutput = Get-IPAPIInfo -Ip $ip
            $IPOutput | add-member -NotePropertyName 'Original Query' -NotePropertyValue $originalQuery -Force
            $ipResultCollection += $IPOutput
            Start-Sleep -s 1
        }
        $count++
    }

    $count = 0
    foreach ($item in $items) {
        Write-Progress -Activity "IP Data Checks" -Status "Merging Data..." -PercentComplete (($count/$items.length)*100)
        $ipresult = $ipResultCollection | Where-Object {$_.'Original Query' -eq $item.$($IpProperty)}
        foreach($entry in $item.psobject.properties.name){
            if ($item.$($entry) -is [array]) {
                #$testy.$($taco) = Compress-Array $testy.$($taco)
                $CopyEntry = $item.$($entry)
                $item.psobject.properties.remove($entry)
                $count2 = 0
                foreach($t in $CopyEntry)
                {
                    if($t.name){
                        $item | Add-Member -NotePropertyName ($t.name+$count2) -NotePropertyValue $t.value
                    } elseif ($t.ID) {
                        $entryValue = $t.ID + ": " + $t.type
                        $item | Add-Member -NotePropertyName ($entry+$count2) -NotePropertyValue $entryValue
                    }
                    $count2++
                }

            }
        }
        foreach ($entry in $ipResult.psobject.properties.name){
            $item | Add-Member -NotePropertyName $entry -NotePropertyValue $ipresult.$($entry)
        }
        $count++
    }
    $Items
}

$export = Merge-IPAPIInfo -Item $auditdata -IpProperty ClientIp
$export | Export-Excel "C:\temp\$FolderName\Audit Data       -$foldername.xlsx"
$export | Group-Object Country | Select-Object Count,Name | Export-Excel "C:\temp\$FolderName\CountryLogins       -$foldername.xlsx" -AutoSize
#$logs | ConvertTo-Json -Depth 99 | Out-File C:\temp\logs.json
$groups = $export | Group-Object operation
foreach($group in $groups){
    $group.group | Export-Excel "C:\temp\$Foldername\$($group.name)       -$foldername.xlsx" -AutoSize -TableStyle Medium2
}
write-host "[+] Logs Completed... Opening Results... "
Invoke-Item  "C:\temp\$Foldername\"
Start-Sleep -s 5
