# C# code - Implemented in SqlCredentialConstructor
new SqlCredential("username1", "doodle_BLOB1")

# C# code - Implemented in SqlCredentialObjectInitializer
new SqlCredential()
{
	UserId = "username2",
	Password = "doodle_BLOB2",
}

# Powershell - Implemented in SqlCredentialPowershell
PS SQLServer:\SQL\Computer\Instance> $SecureString = ConvertTo-SecureString "doodle_BLOB3" -AsPlainText -Force
...
PS SQLServer:\SQL\Computer\Instance> $Instances | New-SqlCredential -Name "MySqlCredential" -Identity "username3" -Secret $SecureString