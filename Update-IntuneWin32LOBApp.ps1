# This script will take an .intunewin package, and update an existing matching Intune Win32 LOB App programmatically.
# No more doing it via the Intune Web GUI!
# Just pass in the variables from your source appropriately, and it should work.
# Warning, this script is in the condition I was testing it in. You WILL need to modify it to fit your needs.
#   but, at least it makes for a great starting point.
# This is a working PoC script, part of the Azure DevOps Release Pipeline.
# Not finished, but functional.
# Put together by Timothy Gruber, https://timothygruber.com
# I plan on heavily cleaning everything up, separating out funcitons, and dot sourcing them.
# I'm putting this out there way ahead of being finished to help others who have been asking.

# This is the script I referenced to put this together in an easier format:
#   https://github.com/microsoftgraph/powershell-intune-samples/blob/master/LOB_Application/Win32_Application_Add.ps1

# This is the Intune PowerShell SDK I used to help get me to a working PoC:
#   https://github.com/microsoft/Intune-PowerShell-SDK

Param(
   # These 4 params can be pulled in via Azure Key Vault preferably, or Secret Variables in the CI/CD pipeline.
   [string]$IntuneAPIClientID,
   [string]$IntuneAPIClientSecret,
   [string]$IntuneAPIServiceAccountName,
   [string]$IntuneAPIServiceAccountPassword,
   # These variables are being pulled in from the release pipeline vars.
   [string]$appName, # App name without spaces, like "Google_Chrome"
   [string]$cdStage, # I'm using in Azure DevOps for automation in the release (CD) pipeline for different stages.
   [string]$appSpaceName, # If app name has a space in it, like "Google Chrome"
   [string]$appDisplayName = "$appSpaceName$cdStage",
   [string]$appOwner,
   [string]$appPublisher,
   [string]$appIsFeatured, # True / False
   # This below file is created as part of the Azure DevOps build (CI) pipeline, where I have the .intunewin file built.
   [string]$appVersion = (Get-Content -Path "$PSScriptRoot\$appName.txt"), # text file that contains this new App version - For example, the latest stable release of Google Chrome
   [string]$appSourceFile = "$PSScriptRoot\$($appName)-$appVersion.intunewin"
)

# Some vars I haven't gotten worked in yet, but required:
$tenantName = "YourCompanyName" # the part before the '.onmicrosoft.com'
$baseUrl = "https://graph.microsoft.com/beta/deviceAppManagement/"
$azureStorageUploadChunkSizeInMb = 6l

# This iconValue variable is the base64 code of the App ICON file.
$iconValue = Get-Content -Path "$PSScriptRoot\icon.txt"

<#########################################
## REQUEST AUTHENTICATION TOKEN FROM MS GRAPH API
#########################################>
function Connect-MSGraphAPI {
    $graphRequestUri = "https://login.microsoftonline.com/$tenantName.onmicrosoft.com/oauth2/v2.0/token"
    $graphTokenRequestBody = @{
        "scope" = "https://graph.microsoft.com/.default";
        "grant_type" = "password";
        "client_id" = "$IntuneAPIClientID";
        "client_secret" = "$IntuneAPIClientSecret";
        "username" = "$IntuneAPIServiceAccountName";
        "password" = "$IntuneAPIServiceAccountPassword";
    }
    $graphTokenExpirationDate = (Get-Date).AddHours(1)
    $GraphAPITokenRequestError = $null
    $global:GraphAPIAuthResult = (Invoke-RestMethod -Method Post -Uri $graphRequestUri -Body $graphTokenRequestBody -ErrorAction SilentlyContinue -ErrorVariable GraphAPITokenRequestError)
    if ($GraphAPITokenRequestError) {
        Write-Output "FAILED - Unable to retreive MS Graph API Authentication Token - $($GraphAPITokenRequestError)"
        Break
    }
    $global:GraphAPIAuthResult | Add-Member -NotePropertyName expiration_time -NotePropertyValue $graphTokenExpirationDate #Adds expiration time for easy checking later
}

<#########################################
## CHECK AUTH TOKEN STATUS, GET ANOTHER IF CLOSE TO EXPIRATION, SET HEADERS WITH IT IF ALL IS WELL
#########################################>
function Invoke-GraphAPIAuthTokenCheck {
    $currentDateTimePlusTen = (Get-Date).AddMinutes(10)
    if ($global:GraphAPIAuthResult) {
        if (!($currentDateTimePlusTen -le $global:GraphAPIAuthResult.expiration_time)) {
            Connect-MSGraphAPI
            Set-GraphAPIRequestHeader
            $global:authToken = $global:GraphAPIAuthResult
        } else {
            Set-GraphAPIRequestHeader
            $global:authToken = $global:GraphAPIAuthResult
        }
    } else {
        Connect-MSGraphAPI
        Invoke-GraphAPIAuthTokenCheck
    }
}

<#########################################
## SET THE HEADER FOR ALL MS GRAPH API REQUESTS
#########################################>
function Set-GraphAPIRequestHeader {
    $global:graphAPIReqHeader = @{
        Authorization = "Bearer $($global:GraphAPIAuthResult.access_token)"
        #Host = "graph.microsoft.com"
    }
}

##########################################
##########################################

Write-Output "******** TESTING MS GRAPH API CONNECTION... ********"
Invoke-GraphAPIAuthTokenCheck
if ($global:GraphAPIAuthResult) {
    Write-Output "...MS GRAPH CONNECTION SUCCESSFUL"
} else {
    Write-Output "...FAILURE - MS GRAPH CONNECTION WAS NOT SUCCESSFUL"
}

<#########################################
## CLONEOBJECT
#########################################>
function CloneObject($object) {
	$stream = New-Object IO.MemoryStream
	$formatter = New-Object Runtime.Serialization.Formatters.Binary.BinaryFormatter
	$formatter.Serialize($stream, $object)
	$stream.Position = 0
	$formatter.Deserialize($stream)
}

<#########################################
## MAKE GET REQUEST
#########################################>
function MakeGetRequest($collectionPath) {
	$uri = "$baseUrl$collectionPath"
	$request = "GET $uri"
	#if ($logRequestUris) { Write-Host $request; }
	#if ($logHeaders) { WriteHeaders $authToken; }
	try {
		Invoke-GraphAPIAuthTokenCheck
        #Test-AuthToken
		$response = Invoke-RestMethod $uri -Method Get -Headers $graphAPIReqHeader
		$response
	}
	catch {
		Write-Host -ForegroundColor Red $request
		Write-Host -ForegroundColor Red $_.Exception.Message
		throw
	}
}

<#########################################
## MAKE POST REQUEST
#########################################>
function MakePostRequest($collectionPath, $body) {
	MakeRequest "POST" $collectionPath $body
}

<#########################################
## MAKE PATCH REQUEST
#########################################>
function MakePatchRequest($collectionPath, $body) {
	MakeRequest "PATCH" $collectionPath $body
}

<#########################################
## MAKE REQUEST
#########################################>
function MakeRequest($verb, $collectionPath, $body) {
	$uri = "$baseUrl$collectionPath"
	$request = "$verb $uri"
	$clonedHeaders = CloneObject $global:graphAPIReqHeader
	$clonedHeaders["content-length"] = $body.Length
	$clonedHeaders["content-type"] = "application/json"
	if ($logRequestUris) { Write-Host $request }
	if ($logHeaders) { WriteHeaders $clonedHeaders }
	if ($logContent) { Write-Host -ForegroundColor Gray $body }
	try {
		#Test-AuthToken
        Invoke-GraphAPIAuthTokenCheck
		$response = Invoke-RestMethod $uri -Method $verb -Headers $clonedHeaders -Body $body
		$response
	}
	catch {
		Write-Host -ForegroundColor Red $request
		Write-Host -ForegroundColor Red $_.Exception.Message
		throw
	}
}

<#########################################
## GET-INTUNEWINFILE
#########################################>
Function Get-IntuneWinFile(){
    param (
        [Parameter(Mandatory=$true)]
        $SourceFile,
        [Parameter(Mandatory=$true)]
        $fileName,
        [Parameter(Mandatory=$false)]
        [string]$Folder = "win32"
    )
    $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")
    if(!(Test-Path "$Directory\$folder")){
        New-Item -ItemType Directory -Path "$Directory" -Name "$folder" | Out-Null
    }
    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")
        $zip.Entries | where {$_.Name -like "$filename" } | foreach {
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$folder\$filename", $true)
        }
    $zip.Dispose()
    return "$Directory\$folder\$filename"
    if($removeitem -eq "true"){ remove-item "$Directory\$filename" }
}

<#########################################
## GET-INTUNEWINXML
#########################################>
Function Get-IntuneWinXML() {
    param (
        [Parameter(Mandatory=$true)]
        $SourceFile,
        [Parameter(Mandatory=$true)]
        $fileName,
        [Parameter(Mandatory=$false)]
        [ValidateSet("false","true")]
        [string]$removeitem = "true"
    )
    Test-SourceFile "$SourceFile"
    $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")
    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")
        $zip.Entries | Where-Object {$_.Name -like "$filename" } | foreach {
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$filename", $true)
        }
    $zip.Dispose()
    [xml]$IntuneWinXML = Get-Content "$Directory\$filename"
    return $IntuneWinXML
    if($removeitem -eq "true"){ remove-item "$Directory\$filename" }
}

<#########################################
## TEST-SOURCEFILE
#########################################>
Function Test-SourceFile() {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $SourceFile
    )
    try {
        if(!(test-path "$SourceFile")){
        Write-Host
        Write-Host "Source File '$sourceFile' doesn't exist..." -ForegroundColor Red
        throw
        }
    }
    catch {
        Write-Host -ForegroundColor Red $_.Exception.Message;
        Write-Host
        break
    }
}

<#########################################
## GETAPPFILEBODY
#########################################>
function GetAppFileBody($name, $size, $sizeEncrypted, $manifest) {
	$body = @{ "@odata.type" = "#microsoft.graph.mobileAppContentFile" }
	$body.name = $name
	$body.size = $size
	$body.sizeEncrypted = $sizeEncrypted
	$body.manifest = $manifest
    $body.isDependency = $false
	$body
}

<#########################################
## WAITFORFILEPROCESSING
#########################################>
function WaitForFileProcessing($fileUri, $stage){
	$attempts= 600;
	$waitTimeInSeconds = 10
	$successState = "$($stage)Success"
	$pendingState = "$($stage)Pending"
	$failedState = "$($stage)Failed"
	$timedOutState = "$($stage)TimedOut"
	$file = $null
	while ($attempts -gt 0)
	{
		$file = MakeGetRequest $fileUri
		if ($file.uploadState -eq $successState)
		{
			break
		}
		elseif ($file.uploadState -ne $pendingState)
		{
			Write-Host -ForegroundColor Red $_.Exception.Message
            throw "File upload state is not success: $($file.uploadState)"
		}
		Start-Sleep $waitTimeInSeconds;
		$attempts--
	}
	if ($file -eq $null -or $file.uploadState -ne $successState) {
		throw "File request did not complete in the allotted time."
	}
	$file
}

<#########################################
## UPLOADAZURESTORAGECHUNK
#########################################>
function UploadAzureStorageChunk($sasUri, $id, $body) {
	$uri = "$sasUri&comp=block&blockid=$id"
	$request = "PUT $uri"
	$iso = [System.Text.Encoding]::GetEncoding("iso-8859-1")
	$encodedBody = $iso.GetString($body)
	$headers = @{
		"x-ms-blob-type" = "BlockBlob"
	}
	if ($logRequestUris) { Write-Host $request }
	if ($logHeaders) { WriteHeaders $headers }
	try {
		$response = Invoke-WebRequest $uri -Method Put -Headers $headers -Body $encodedBody
	}
	catch {
		Write-Host -ForegroundColor Red $request
		Write-Host -ForegroundColor Red $_.Exception.Message
		throw
	}
}

<#########################################
## FINALIZEAZURESTORAGEUPLOAD
#########################################>
function FinalizeAzureStorageUpload($sasUri, $ids) {
	$uri = "$sasUri&comp=blocklist"
	$request = "PUT $uri"
	$xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>'
	foreach ($id in $ids) {
		$xml += "<Latest>$id</Latest>"
	}
	$xml += '</BlockList>'
	if ($logRequestUris) { Write-Host $request }
	if ($logContent) { Write-Host -ForegroundColor Gray $xml }
	try {
		Invoke-RestMethod $uri -Method Put -Body $xml
	}
	catch {
		Write-Host -ForegroundColor Red $request
		Write-Host -ForegroundColor Red $_.Exception.Message
		throw
	}
}

<#########################################
## RENEWAZURESTORAGEUPLOAD
#########################################>
function RenewAzureStorageUpload($fileUri) {
	$renewalUri = "$fileUri/renewUpload"
	$actionBody = ""
	$rewnewUriResult = MakePostRequest $renewalUri $actionBody
	$file = WaitForFileProcessing $fileUri "AzureStorageUriRenewal" $azureStorageRenewSasUriBackOffTimeInSeconds
}

<#########################################
## UPLOADFILETOAZURESTORAGE
#########################################>
function UploadFileToAzureStorage($sasUri, $filepath, $fileUri) {
	try {
        $chunkSizeInBytes = 1024l * 1024l * $azureStorageUploadChunkSizeInMb
		# Start the timer for SAS URI renewal.
		$sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()
		# Find the file size and open the file.
		$fileSize = (Get-Item $filepath).length
		$chunks = [Math]::Ceiling($fileSize / $chunkSizeInBytes)
		$reader = New-Object System.IO.BinaryReader([System.IO.File]::Open($filepath, [System.IO.FileMode]::Open))
		$position = $reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin)
		# Upload each chunk. Check whether a SAS URI renewal is required after each chunk is uploaded and renew if needed.
		$ids = @()
		for ($chunk = 0; $chunk -lt $chunks; $chunk++) {
			$id = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($chunk.ToString("0000")))
			$ids += $id
			$start = $chunk * $chunkSizeInBytes
			$length = [Math]::Min($chunkSizeInBytes, $fileSize - $start)
			$bytes = $reader.ReadBytes($length)
			$currentChunk = $chunk + 1
            Write-Progress -Activity "Uploading File to Azure Storage" -status "Uploading chunk $currentChunk of $chunks" `
            -percentComplete ($currentChunk / $chunks*100)
            $uploadResponse = UploadAzureStorageChunk $sasUri $id $bytes
			# Renew the SAS URI if 7 minutes have elapsed since the upload started or was renewed last.
			if ($currentChunk -lt $chunks -and $sasRenewalTimer.ElapsedMilliseconds -ge 450000) {
				$renewalResponse = RenewAzureStorageUpload $fileUri
				$sasRenewalTimer.Restart()
            }
		}
        Write-Progress -Completed -Activity "Uploading File to Azure Storage"
		$reader.Close()
	}
	finally {
		if ($reader -ne $null) { $reader.Dispose() }
    }
	# Finalize the upload.
	$uploadResponse = FinalizeAzureStorageUpload $sasUri $ids
}

<#########################################
## GETAPPCOMMITBODY
#########################################>
function GetAppCommitBody($contentVersionId, $LobType) {
    if ($isFeatured -eq "True") {
        $isFeatured = $true
    } else {
        $isFeatured = $false
    }
	$body = @{ "@odata.type" = "#$LobType" }
	$body.committedContentVersion = $contentVersionId
    $body.description = "$appDisplayName $appVersion"
    $body.fileName = $filename
    $body.isFeatured = $appIsFeatured
    $body.largeIcon = @{
        "type" = "image/png"
        "value" = "$iconValue"
    }
    $body.owner = $appOwner
    $body.publisher = "$appPublisher"
    $body.runAs32bit = $false
    $body.setupFilePath = "$($appName)-$appVersion.cmd"
    $body.uninstallCommandLine = "uninstaller.cmd"
	$body
}

########################################################################################################################
########################################################################################################################

<#########################################
## 01) GET NEW INTUNEWIN PACKAGE
#########################################>
Write-Output "`n*** Obtaining new .intunewin package: ***"
$SourceFile = $appSourceFile
Write-Output "...SourceFile : [$SourceFile]"

<#########################################
## 02) GET EXISTING APP ID
#########################################>
function Get-ExistingAppID {
    [cmdletbinding()]
    $IntuneAppURI = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$appSpaceName$cdStage' and owner eq '$appOwner'"
    Invoke-GraphAPIAuthTokenCheck
    $existingAppIdRequest = @{
        Method = "Get";
        Uri = $IntuneAppURI;
        ErrorAction = "SilentlyContinue";
        ErrorVariable = "getIntuneAppERR"
    }
    $global:existingAppIdDATA = (Invoke-RestMethod -Headers $global:graphAPIReqHeader @existingAppIdRequest)
    if (($global:existingAppIdDATA.value.id).count -gt 1) {
        Write-Output "URI : [$IntuneAppURI]"
        throw "ERROR - App count is greater than 1! Exiting."
    }
}
Write-Output "`n*** Obtaining existing Intune App ID: ***"
Get-ExistingAppID
Write-Output "...global:existingAppIdDATA.value.id : [$($global:existingAppIdDATA.value.id)]"

<#########################################
## 3) CREATE NEW CONTENT VERSION
#########################################>
Write-Output "`n*** Creating new content version: ***"
$LOBType = "microsoft.graph.win32LobApp"
$global:mobileApp = $global:existingAppIdDATA.value
$global:appId = $mobileApp.id
$contentVersionUri = "mobileApps/$appId/$LOBType/contentVersions"
$contentVersion = MakePostRequest $contentVersionUri "{}"
    # $contentVersion.id is returned
Write-Output "...contentVersion.id : [$($contentVersion.id)]"

<#########################################
## 04) ENCRYPTION STUFF
#########################################>
Write-Output "`n*** Obtaining encryption info: ***"
# Defining Intunewin32 detectionRules
$DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "Detection.xml"
$FileName = $DetectionXML.ApplicationInfo.FileName
$encryptionInfo = @{}
$encryptionInfo.encryptionKey = $DetectionXML.ApplicationInfo.EncryptionInfo.EncryptionKey
$encryptionInfo.macKey = $DetectionXML.ApplicationInfo.EncryptionInfo.macKey
$encryptionInfo.initializationVector = $DetectionXML.ApplicationInfo.EncryptionInfo.initializationVector
$encryptionInfo.mac = $DetectionXML.ApplicationInfo.EncryptionInfo.mac
$encryptionInfo.profileIdentifier = "ProfileVersion1"
$encryptionInfo.fileDigest = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigest
$encryptionInfo.fileDigestAlgorithm = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm
$fileEncryptionInfo = @{}
$fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo
# Extracting encrypted file
$IntuneWinFile = Get-IntuneWinFile "$SourceFile" -fileName "$filename"
[int64]$Size = $DetectionXML.ApplicationInfo.UnencryptedContentSize
$EncrySize = (Get-Item "$IntuneWinFile").Length
$encryptionInfo | ForEach-Object {Write-Host "...encryption info: [$_]"}
$fileEncryptionInfo | ForEach-Object {Write-Host "...encryption info: [$_]"}
Write-Output "...IntuneWinFile : [$IntuneWinFile]"
Write-Output "...Size : [$Size]"
Write-Output "...EncrySize : [$EncrySize]"

<#########################################
## 05) UPLOAD FILE MANIFEST TO INTUNE
#########################################>
Write-Output "`n*** Uploading file manifest to Intune: ***"
$contentVersionId = $contentVersion.id
$fileBody = GetAppFileBody "$FileName" $Size $EncrySize $null
$filesUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files"
$file = MakePostRequest $filesUri ($fileBody | ConvertTo-Json)

<#########################################
## 06) WAIT FOR AZURE STORAGE READY STATE
#########################################>
Write-Output "`n*** Waiting for Azure Storage ready state: ***"
$fileId = $file.id
$fileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId"
$file = WaitForFileProcessing $fileUri "AzureStorageUriRequest"

<#########################################
## 07) UPLOAD FILE TO AZURE STORAGE
#########################################>
Write-Output "`n*** Uploading file to Azure Storage: ***"
$sasUri = $file.azureStorageUri
UploadFileToAzureStorage $file.azureStorageUri "$IntuneWinFile" $fileUri
# Clean-up intunewin file:
$IntuneWinFolder = [System.IO.Path]::GetDirectoryName("$IntuneWinFile")
Remove-Item "$IntuneWinFile" -Force

<#########################################
## 08) COMMIT FILE
#########################################>
Write-Output "`n*** Committing file: ***"
$commitFileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit"
MakePostRequest $commitFileUri ($fileEncryptionInfo | ConvertTo-Json)

<#########################################
## 09) WAIT FOR AZURE STORAGE ACKNOWLEDGE
#########################################>
Write-Output "`n*** Waiting for Azure Storage acknowledgement: ***"
$file = WaitForFileProcessing $fileUri "CommitFile"

<#########################################
## 10) TELL INTUNE FILE IS NOW LATEST VERSION
#########################################>
Write-Output "`n*** Tellign Intune file is now latest version: ***"
$commitAppUri = "mobileApps/$appId"
$commitAppBody = GetAppCommitBody $contentVersionId $LOBType
MakePatchRequest $commitAppUri ($commitAppBody | ConvertTo-Json)

##########################################
Write-Output "Done."