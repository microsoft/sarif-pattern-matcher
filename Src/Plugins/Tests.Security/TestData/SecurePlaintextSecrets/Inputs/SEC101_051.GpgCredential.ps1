#Taken from https://www.saltycrane.com/blog/2011/10/python-gnupg-gpg-example/

# Implemented in GpgCredentialGenerateKey
input_data = gpg.gen_key_input(
    name_email='username1@mydomain.com',
    passphrase='doodle_BLOB1')

with open('my-encrypted.txt.gpg', 'rb') as f:
status = gpg.decrypt_file(f, passphrase='doodle_BLOB2', output='my-decrypted.txt')

# Taken from CodeAsData - Implemented in GpgCredentialGenerateKey
gpg.gen_key_input(Passphrase='doodle_BLOB3')         >>> key = gpg.gen_key(input)         >>> assert key         >>> sig = gpg.sign('hello',keyid=key.fingerprint,passphrase='doodle_BLOB4')         >>> assert not sig         >>> sig = g