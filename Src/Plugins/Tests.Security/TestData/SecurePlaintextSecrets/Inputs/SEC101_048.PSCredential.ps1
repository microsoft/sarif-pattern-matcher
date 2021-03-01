# Implemented in PSCredentialConstructor
$domainCredential = New-Object System.Management.Automation.PSCredential ("REDMOND\v-jwinkler", "doodle_BLOB1");

# Implemented in PSCredentialConstructor
 PSCredential Credential = new PSCredential ( "username2" , "doodle_BLOB2");

 # Implemented in PSCredentialObjectInitializer
 something = new PSCredential()
 {
	UserName = "username3",
	Password = "doodle_BLOB3",
 }

 # Example from https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-credential?view=powershell-7.1
 # Implemented in PSCredentialPowershell
 $PWord = ConvertTo-SecureString -String "doodle_BLOB6" -AsPlainText -Force
 $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord