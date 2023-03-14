Set-Location C:/Users/mumbi/OneDrive/Desktop/SKILLS/PROJECTS/Computer_InfoSec_1996/FIM
Add-Type -AssemblyName system.speech
$voice= New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer

$FileVoiceAndText = "PLEASE SELECT WHAT YOU WOULD LIKE TO BEGIN WITH"
$CreateBaselineText ="A) Create and Update baseline file?"
$StartMonitorCheck = "B) Monitor files with saved Baseline?"

Write-Host "********************************************************"
Write-Host $FileVoiceAndText
$voice.Speak($FileVoiceAndText)
Write-Host "##############################################"
Write-Host $CreateBaselineText
Write-Host $StartMonitorCheck
Write-Host "##############################################"
$response = Read-Host -Prompt "Please enter 'A' or 'B'"
Write-Host "*****************************************"


Function Calculate-File-Hash($filepath){
$filehash = Get-FileHash -Path $filepath -Algorithm SHA512
return $filehash
}

Function Erase-Baseline-If-Already-Exists(){
  $baselineExists = Test-Path -Path .\baseline.txt

  if($baselineExists){
    
    # Delete it 
      Remove-Item -Path .\baseline.txt
  
  }
 
}

if ($response -eq "A".ToUpper()) {
# Delete baseline.txt if it already exists
  Erase-Baseline-If-Already-Exists 

# Calculate Hash from the target files and store in baseline.txt
# Collect all files in the target folder
$files = Get-ChildItem -Path .\Files

# for file, calculate the bash, and write to baseline.txt
 foreach ($f in $files){
   $hash = Calculate-File-Hash $f.FullName
   "$($hash.Path)|$($hash.Hash)" | Out-File -FilePath .\baseline.txt -Append
    $voice.Speak(" Baseline file has been created and updated!")
 
   }

}

elseif ($response -eq "B".ToUpper()) {

    $fileHashDictionary = @{}

# Load file|hash from baseline.txt and store them in a dictionary
    $filePathsAndHashes = Get-Content -Path .\baseline.txt
    
    foreach ($f in $filePathsAndHashes) {
             $fileHashDictionary.add($f.Split("|")[0],$f.Split("|")[1])
    }
     $fileHashDictionary.keys


# Begin continously monitoring files with saved Baseline

   While($true){
   start-Sleep -Seconds 1

    $files = Get-ChildItem -Path .\Files
   
 # For each file, calculate the hash, and write to baseline.txt
        foreach ($f in $files) {
            $hash = Calculate-File-Hash $f.FullName
            #"$($hash.Path)|$($hash.Hash)" | Out-File -FilePath .\baseline.txt -Append
     
 # Notify if a new file has been created
            if ($fileHashDictionary[$hash.Path] -eq $null) {
                # A new file has been created!
                Write-Host "$($hash.Path) has been created!" -ForegroundColor Green
                $voice.Speak("($key.Path) has been created!!!!")
            }
  # Notify if a new file has been changed
                if ($fileHashDictionary[$hash.Path] -eq $hash.Hash) {
                    # The file has not changed
                    Write-Host "$($hash.Path) has not changed!!!" -ForegroundColor Blue
                    $voice.Speak("($key.Path) has not changed!!!!")
                }

               else {
  # File file has been compromised!, notify the user
                    Write-Host "$($hash.Path) has been altered or changed!!!" -ForegroundColor Yellow
                     $voice.Speak("($key.Path) has been altered or changed!!!!")
                }      

             }

      foreach ($key in $fileHashDictionary.Keys) {
                $baselineFileStillExists = Test-Path -Path $key
            if (-Not $baselineFileStillExists) {
  # One of the baseline files must have been deleted, notify the user
                Write-Host "$($key) has been deleted!" -ForegroundColor Red -BackgroundColor Gray
                 $voice.Speak("($key.Path) has been deleted!")



          }

  
       }  

    } 

}
