$hashes = @( "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0",
            "097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e",
            "2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1",
            "65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5",
            "511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1",
            "4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea",
            "811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d",
            "1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944")
$filePaths = @(  "C:\inetpub\wwwroot\aspnet_client\",
                "C:\inetpub\wwwroot\aspnet_client\system_web\",
                "c:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\",
                "c:\Program Files(x86)\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\",
                "C:\Exchange\FrontEnd\HttpProxy\owa\auth\")

Write-Host "Checking for Webshells"
foreach($filePath in $filePaths){
    if (Test-Path $filePath){
        cd $filePath;
        ls | % {$hash = Get-FileHash $_.Name; if ($hashes -contains $hash.Hash) { Write-Host $hash.Path}}
        ls | % {if ($_.Name.Contains(".aspx")) { $fileContent = Get-Content $_.Name; if ($fileContent.Contains("Jscript") -or $fileContent.Contains("<%System.IO.File.WriteAllText(Request.Item[`"p`"],Request.Item[`"c`"]);%>")) {Write-Host $_.Name} } }
    }
}

#CVE-2021-26858
Write-Host "Checking CVE-2021-26858 IOC"
findstr /snip /c:"Download failed and temporary file" "%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log"
#CVE-2021-26857
Write-Host "Checking CVE-2021-26857 IOC"
Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error | Where-Object { $_.Message -like "*System.InvalidCastException*" }
#CVE-2021-27065 
Write-Host "Checking CVE-2021-27065  IOC"
Select-String -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" -Pattern 'Set-.+VirtualDirectory'
#CVE-2021-26855
Write-Host "Checking CVE-2021-26855 IOC"
Import-Csv -Path (Get-ChildItem -Recurse -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy" -Filter '*.log' -ErrorAction SilentlyContinue).FullName | Where-Object {  $_.AuthenticatedUser -eq '' -and $_.AnchorMailbox -like 'ServerInfo~*/*' } | select DateTime, AnchorMailbox
