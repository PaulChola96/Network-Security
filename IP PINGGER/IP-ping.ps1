Set-Location "C:\Users\mumbi\OneDrive\Desktop\SKILLS\PROJECTS\Computer_InfoSec_1996\IP PINGGER"

Add-Type -AssemblyName System.Speech

$Voice = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
$ipAddresses = "192.168.0.1", "8.8.8.8", "127.1" # Replace with the IP addresses you want to ping, separated by commas
$nslookups = "www.google.com", "www.microsoft.com" # Replace with the URLs you want to lookup, separated by commas
$outputFile = "ping-results.txt" # Replace with the filename and path where you want to save the results
$nsoutputFile = "nslookup-results.txt"  # Replace with the filename and path where you want to save the results  

foreach ($ipAddress in $ipAddresses) {
    # Ping the IP address and save the output to a variable
    $pingOutput = Test-Connection -ComputerName $ipAddress -Count 1
    
    # Save the output to a file
    $pingOutput | Out-File $outputFile -Append
}

foreach($nslookup in $nslookups) {
    # lookup IP address and save the output to a variable
    $nsLookupOut = Resolve-DnsName -Name $nslookup -Type A -Server 8.8.8.8

    # Save the output to a file
    $nsLookupOut | Out-File $nsoutputFile -Append
}

Function Created-File {
    $pinglist = Test-Path -Path .\ping-results.txt

    if ($pinglist) {
        Write-Host "Ping results file has been created"
        $Voice.Speak("Ping results file has been created and updated")
    }
}

Function Created-File-Nslookup {
    $nslist = Test-Path -Path .\nslookup-results.txt

    if ($nslist) {
        Write-Host "NSLookup results file has been created"
        $Voice.Speak("NSLookup results file has been created and updated")
    }
}

Created-File
Created-File-Nslookup
