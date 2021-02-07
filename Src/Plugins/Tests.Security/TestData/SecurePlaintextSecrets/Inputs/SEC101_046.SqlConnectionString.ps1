# This is a well-formed but invalid ODBC sql connection string
jdbc:sqlserver://some-database-name.database.windows.net:1433;database=tse-internal-spam-testing;user=username@some-database-name;password=password;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;

# This is a well-formed but invalid JDBC sql connection string
Driver={ODBC Driver 13 for SQL Server};Server=tcp:some-database-name.database.windows.net,1433;Database=tse-internal-spam-testing;Uid=username;Pwd=password;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;

# This is a well-formed but invalid PHP SQL connection string
new PDO("sqlsrv:server = tcp:some-database-name.database.windows.net,1433; Database = some-database-name", "username", "password");

# Xml style
<connectionStrings>
    <add name="YourConnectionStringKey" 
        providerName="System.Data.SqlClient"
        connectionString="Data Source=server-name;Initial Catalog=catalog-db;User ID=username;Password=password;" />
    <add name="YourConnectionStringKey" 
        providerName="System.Data.SqlClient"
        connectionString="Password=password;User ID=username;Initial Catalog=catalog-db;Data Source=server-name;" />
    <add name="YourConnectionStringKey" 
        providerName="System.Data.SqlClient"
        connectionString="Initial Catalog=catalog-db;Data Source=server-name;Password=password;User ID=username;" />

    # NoMatch
    <add name="YourConnectionStringKey" 
        providerName="System.Data.SqlClient"
        connectionString="Initial Catalog=catalog-db;Data Source=server-name;User ID=username;User ID=username;" />

</connectionStrings>

# AppSettings style
<appSettings>
  <add key="ConnectionString" value="Data Source=server-name;Initial Catalog=catalog-db;User ID=username;Password=password;" />
  <add key="ConnectionString" value="Password=password;User ID=username;Initial Catalog=catalog-db;Data Source=server-name;" />
  <add key="ConnectionString" value="Initial Catalog=catalog-db;Data Source=server-name;Password=password;User ID=username;" />
</appSettings>

# Should be ignored, since is localhost/(local)/127.0.0.1
jdbc:sqlserver://localhost;database=tse-internal-spam-testing;user=username@some-database-name;password=password;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;
jdbc:sqlserver://(local);database=tse-internal-spam-testing;user=username@some-database-name;password=password;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;
jdbc:sqlserver://127.0.0.1;database=tse-internal-spam-testing;user=username@some-database-name;password=password;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;
