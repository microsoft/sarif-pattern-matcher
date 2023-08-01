# Implemented in CredentialObjectConstructor
$domainCredential = New-Object System.Management.Automation.PSCredential ("REDMOND\username1", "doodle_BLOB1");

 PSCredential Credential = new PSCredential ( "username2" , "doodle_BLOB2");

 new SqlCredential("username3", "doodle_BLOB3")

 # Implemented in CredentialObjectInitializer
 something = new PSCredential()
 {
	UserName = "username4",
	Password = "doodle_BLOB4",
 }

 new SqlCredential()
{
	UserId = "username5",
	Password = "doodle_BLOB5",
}