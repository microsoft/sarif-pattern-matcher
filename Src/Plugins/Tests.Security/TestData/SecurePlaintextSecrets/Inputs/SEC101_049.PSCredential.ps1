# Implemented in PSCredentialConstructor
$domainCredential = New-Object System.Management.Automation.PSCredential ("REDMOND\username1", "doodle_BLOB1");

# Implemented in PSCredentialConstructor
 PSCredential Credential = new PSCredential ( "username2" , "doodle_BLOB2");

 # Implemented in PSCredentialObjectInitializer
 something = new PSCredential()
 {
	UserName = "username3",
	Password = "doodle_BLOB3",
 }