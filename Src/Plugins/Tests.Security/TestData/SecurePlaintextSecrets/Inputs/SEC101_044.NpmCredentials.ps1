# auth example (user1:password1)
registry=https://registry.npmjs.org
always-auth=true
_auth=dXNlcjE6cGFzc3dvcmQx

************************************************************
************************************************************
************************************************************
************************************************************

# password example
registry=https://registry.npmjs.org
always-auth=true
_password=cGFzc3dvcmQy

************************************************************
************************************************************
************************************************************
************************************************************

# user+password example
registry=https://registry.npmjs.org
always-auth=true
username=user2
_password=cGFzc3dvcmQy

************************************************************
************************************************************
************************************************************
************************************************************

registry=https://registry.npmjs.org
always-auth=true
_password=cGFzc3dvcmQy
username=user3

************************************************************
************************************************************
************************************************************
************************************************************

# invalid password example
registry=https://registry.npmjs.org
always-auth=true
username=user2
_password=invalid_password1

************************************************************
************************************************************
************************************************************
************************************************************

# invalid password example (password should have a number)
registry=https://registry.npmjs.org
always-auth=true
_password=passwordwithoutnumbers
username=user3