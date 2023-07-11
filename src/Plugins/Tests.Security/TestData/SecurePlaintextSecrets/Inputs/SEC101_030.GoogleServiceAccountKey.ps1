# Top 2 taken from https://cloud.google.com/iam/docs/creating-managing-service-account-keys

{
  "type": "service_account",
  "project_id": "project-id1",
  "private_key_id": "keyId1",
  "private_key": "-----BEGIN PRIVATE KEY-----\n11111111\n-----END PRIVATE KEY-----\n",
  "client_email": "service-account-email1@server.com",
  "client_id": "client-id1",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://accounts.google.com/o/oauth2/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/service-account-email"
}

{
  "name": "projects/project-id1/serviceAccounts/service-account-email2@server.com/keys/keyId2",
  "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
  "privateKeyData": "22222222",
  "validAfterTime": "date",
  "validBeforeTime": "date",
  "keyAlgorithm": "KEY_ALG_RSA_2048"
}

# Masked from real results
"private_key_id": "0123456789abcdefghijklmnopqrstuvwxyz",   "private_key": "-----BEGIN PRIVATE KEY-----\n33333333333333333333three/three\three+three\n-----END PRIVATE KEY-----\n",   "client_email": "email@server.stuff.otherstuff.com",   "client_id": "333333333333333333333333"