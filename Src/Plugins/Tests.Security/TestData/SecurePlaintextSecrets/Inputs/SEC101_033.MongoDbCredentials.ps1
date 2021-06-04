mongodb://dbuser1:<password>@database.com:10250/database

mongodb+srv://dbuser2:<password>@database.com/

"mongodb": "mongodb+srv://dbuser3:<password>@database.com"

<mongodb>mongodb+srv://dbuser4:<password>@database.com<monbodb/>

<add key="MongoProxyServerIP" value="999.9.9.9" />
    <add key="MongoProxyConnection" value="mongodb://localhost:55555" />
    <!--[SuppressMessage("Microsoft.Security", "CS9999:SecretInNextLine")]-->
    <add key="MongoProxyConnectionWithCredentials" value="mongodb://dbuser5:password@localhost:55555/" />
    <!--[SuppressMessage("Microsoft.Security", "CS9999:SecretInNextLine")]-->