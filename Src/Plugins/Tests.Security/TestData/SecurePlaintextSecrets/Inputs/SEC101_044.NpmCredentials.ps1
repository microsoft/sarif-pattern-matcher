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

registry=https://registry.npmjs.org
always-auth=true
_password=passwordwithoutnumbers
username=user3


************************************************************
************************************************************
************************************************************
************************************************************

registry=https://registry.npmjs.org
always-auth=true
username=user2
_password=valid_password1

************************************************************
************************************************************
************************************************************
************************************************************

# Command line representation
npm login -r https://registry.npmjs.org -u user4 -p deadcGFzc3dvcmQy

************************************************************
************************************************************
************************************************************
************************************************************

npm login -r https://registry.npmjs.org -u user5 -p passwordwithoutnumbers