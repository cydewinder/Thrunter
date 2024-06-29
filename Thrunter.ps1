#inspect logs function will review the latest dump of logs for any malicious activity. Anthing found can then be sent to the custom event log for our application.
function inspect-logs {
$log_var = get-content C:\\Users\Administrator\Desktop\Thrunter\log$counter.txt | convertfrom-json
password_spray_hunt
kerberoasting_detection
dc_sync_detection
}

function password_spray_hunt {
$bad_pass_array = @()
foreach ($item in $log_var) { 
if ($item.eventid -eq 4625) {
$bad_pass++
$user_name = $item.ReplacementStrings[5]
$workstation_name = $item.ReplacementStrings[13]
$source_ip = $item.ReplacementStrings[19]
$event_num = $item.index
$bad_pass_array += "$event_num,$user_name,$workstation_name,$source_ip;"
}
}
if ($bad_pass_array.Count -gt 50) {
#creates alert if more than 50 failed logins in past 5 minutes.
write-eventlog -logname "Application" -source "Thrunter" -eventid 101 -entrytype information -message "High Confidence Password Spray Detected `n List of failed logins `n $bad_pass_array"
}
elseif ($bad_pass_array.count -gt 25 -and $bad_pass_array.count -lt 51){
#creates alert if more than 25 failed logins in past 5 minutes.
write-eventlog -logname "Application" -source "Thrunter" -eventid 102 -entrytype information -message "Medium Confidence Password Spray Detected `n List of failed logins `n $bad_pass_array"
}
elseif ($bad_pass_array.count -gt 10 -and $bad_pass_array.count -lt 26 ){
#creates alert if more than 10 failed logins in past 5 minutes.
write-eventlog -logname "Application" -source "Thrunter" -eventid 103 -entrytype information -message "Low Confidence Password Spray Detected `n List of failed logins `n $bad_pass_array"
}
}

function kerberoasting_detection {
	foreach ($item in $log_var) {
	$kerb_log = $item
	$kerb_log_index = $kerb_log.Index
	$kerb_log_machinename = $kerb_log.MachineName
	if ($item -Match "secretservice") {
		write-eventlog -logname "Application" -source "Thrunter" -eventid 201 -entrytype information -message "High Confidence Kerberoasting Detected `n Investigate EventRecordID $kerb_log_index on $kerb_log_machinename `n Use command Get-Eventlog -LogName Security -Index $kerb_log_index"
	}
	elseif ($item.Message -Match "Ticket Encryption Type:\t0x17" -or $item.Message -Match "Ticket Encryption Type:	0x18"){
		write-eventlog -logname "Application" -source "Thrunter" -eventid 202 -entrytype information -message "Medium Confidence Kerberoasting Detected `n Investigate EventRecordID $kerb_log_index on $kerb_log_machinename `n Use command Get-Eventlog -LogName Security -Index $kerb_log_index"
		}
	}
}

function dc_sync_detection {
	foreach ($item in $log_var) {
	$log_index = $item.Index
	if ($item.eventid -eq 4662 -and $item.ReplacementStrings -notlike "*$" -and $item.ReplacementStrings -Match "%%7688\r\n\t\t{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}\r\n\t{19195a5b-6da0-11d0-afd3-00c04fd930c9}\r\n"){
	write-eventlog -logname "Application" -source "Thrunter" -eventid 301 -entrytype information -message "High Confidence DCSync Attack Detected `n Investigate EventRecordID $log_index using command Get-EventLog -LogName Security -Index $log_index"
	}
	elseif ($item.eventid -eq 4662 -and $item.ReplacementStrings -Match "%%7688\r\n\t\t{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}\r\n\t{19195a5b-6da0-11d0-afd3-00c04fd930c9}\r\n"){
			write-eventlog -logname "Application" -source "Thrunter" -eventid 303 -entrytype information -message "Low Confidence DCSync Attack Detected `n Investigate EventRecordID $log_index using command Get-EventLog -LogName Security -Index $log_index"
	}
	}
}

#checks to see if custom logging location has been created on this machine and creates it if it has not been.
$logging = (Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application).pschildname -match "Thrunter"
if ([string]::IsNullOrEmpty($logging)){
new-eventlog -logname Application -source Thrunter -ErrorAction SilentlyContinue
}
#checks to see if honey service account (secretservice) exists, and creates it if needed.
if ((get-aduser -filter "Name -eq 'secretservice'") -eq $null) {
	$pass = get-random
	$bytes = [System.Text.Encoding]::Unicode.GetBytes($pass)
	$enc_pass = [convert]::ToBase64String($bytes)
	$final_pass = Convertto-securestring $enc_pass -Asplaintext -force
	new-aduser -Name "secretservice" -AccountPassword $final_pass
	Enable-adaccount -Identity 'secretservice'
	setspn -S SQL1234/service.project.local secretservice
	[byte[]]$hours = @(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
	set-aduser -identity secretservice -replace @{logonhours = $hours}
}


#sets counter for logfile output
$counter = 1

#main loop that is responsible for dumping the logs and will send the check-in for the agent which will be sent to kibana
while ( 1 -eq 1) {
write-eventlog -logname "Application" -source "Thrunter" -eventid 1 -entrytype information -message "Agent On $env:computername Checked In."
Get-Eventlog -LogName security -After (Get-Date).AddMinutes(-1)| where-object {$_.EventID -eq 4625 -or $_.EventID -eq 4769 -or $_.EventID -eq 4662} | convertto-json | out-file C:\\Users\Administrator\Desktop\Thrunter\log$counter.txt
inspect-logs
$counter = $counter + 1
start-sleep -seconds 60
}