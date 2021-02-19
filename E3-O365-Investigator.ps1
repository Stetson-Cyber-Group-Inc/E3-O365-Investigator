Install-Module ExchangeOnlineManagement
Connect-ExchangeOnline
$Suspect = Read-Host "what email address are we investigating?"
$Company1 = Read-Host "what is the name of the company? (no spaces - this will be the folder name)"
New-Item -ItemType Directory -Force -Path C:\temp\$Company1 | out-null
write-host "[+]....Pulling logs down......"
write-host "[+]....This will take a few min......"
$logs = Search-UnifiedAuditLog -ResultSize 10000 -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -UserIds $Suspect
#$logs = Search-MailboxAuditLog -ResultSize 5000 -StartDate (Get-Date).AddDays(-10) -EndDate (Get-Date) -Identity $Suspect -ShowDetails
#$logs | group-object operations 
$auditdata = $logs.auditdata | ConvertFrom-Json
function Get-IPAPIInfo {
    Param(
        [Parameter(Mandatory = $true)][string]$Ip
    )
     
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
    $ipResult = Invoke-restmethod -method get -uri "http://ip-api.com/json/$($ip)"
    Start-Sleep -s 1
    # Edit this with your key and remove the 2 lines above if you're using the Pro version of IP-API.com (recommended).
    #$ipResult = Invoke-restmethod -method get -uri "http://pro.ip-api.com/json/$($ip)?key=YOURIP-APIKEYHERE"
    $ipResult | Add-Member originalQuery $originalQuery -force
    $ipResult
}
 
function Merge-IPAPIInfo {
    Param(
        [Parameter(Mandatory = $true)][string]$IpProperty,
        [Parameter(Mandatory = $true)][object]$Item
    )
 
    $ips = $item | Sort-Object $IpProperty -Unique
    $ipResultCollection = @()
    foreach($ip in $ips){
        $ipResultCollection += Get-IPAPIInfo -Ip $ip.$($IpProperty) 
    }
 
    foreach ($object in $item) {
        $ipresult = $ipResultCollection | Where-Object {$_.originalQuery -eq $object.$($IpProperty)}
        foreach ($property in $ipresult.psobject.properties.name) {
            $object | add-member $property $ipresult.$($property) -force
        }
    }
 
    $item
} 
$auditdata = Merge-IPAPIInfo -Item $auditdata -IpProperty ClientIp
$auditdata | Group-Object Country | Export-Csv C:\temp\$Company1\CountryLogins.csv
#$logs | ConvertTo-Json -Depth 99 | Out-File C:\temp\logs.json
$groups = $auditdata | Group-Object operation
foreach($group in $groups){ $group.group | Export-Csv C:\temp\$Company1\$($group.name).csv -NoTypeInformation }
write-host "[+] Logs Completed... Opening Results... "
Start C:\temp\$Company1\
Start-Sleep -s 5
