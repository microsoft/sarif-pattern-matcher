# This is a well-formed but invalid ODBC sql connection string
jdbc:sqlserver://servername1.database.windows.net:1433;database=database1;user=username1@some-database-name;password=password1;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;

# This is a well-formed but invalid JDBC sql connection string
Driver={ODBC Driver 13 for SQL Server};Server=tcp:servername2.database.windows.net,1433;Database=database2;Uid=username2;Pwd=password2;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;

# This is a well-formed but invalid PHP SQL connection string
new PDO("sqlsrv:server = tcp:servername3.database.windows.net,1433; Database = databse3", "username3", "password3");

# Xml style
<connectionStrings>
    <add name="YourConnectionStringKey" 
        providerName="System.Data.SqlClient"
        connectionString="Data Source=servername4;Initial Catalog=database4;User ID=username4;Password=password4;" />
    <add name="YourConnectionStringKey" 
        providerName="System.Data.SqlClient"
        connectionString="Password=password5;User ID=username5;Initial Catalog=database5;Data Source=database5;" />
    <add name="YourConnectionStringKey" 
        providerName="System.Data.SqlClient"
        connectionString="Initial Catalog=database6;Data Source=servername6;Password=password6;User ID=username6;" />

    # NoMatch missing a password
    <add name="YourConnectionStringKey" 
        providerName="System.Data.SqlClient"
        connectionString="Initial Catalog=database7;Data Source=servername7;User ID=username7;User ID=username7;" />
</connectionStrings>

<Connection>
    <SqlServer>Data Source=servername15;Initial Catalog=database15;User ID=username15;Password=password15</SqlServer>
</Connection>

# AppSettings style
<appSettings>
  <add key="ConnectionString" value="Data Source=servername8;Initial Catalog=database8;User ID=username8;Password=password8;" />
  <add key="ConnectionString" value="Password=password9;User ID=username9;Initial Catalog=database9;Data Source=servername9;" />
  <add key="ConnectionString" value="Initial Catalog=database10;Data Source=servername10;Password=password10;User ID=username10;" />
  <add key="ConnectionString" value="Data Source=servername17;Initial Catalog=database17;User ID=username17;Password=password17" />
</appSettings>

# Should be ignored, since is localhost/(local)/127.0.0.1
jdbc:sqlserver://localhost;database=database11;user=username11@some-database-name;password=password11;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;
jdbc:sqlserver://(local);database=database12;user=username12@some-database-name;password=password12;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;
jdbc:sqlserver://127.0.0.1;database=database13;user=username13@some-database-name;password=password13;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;


[global::System.Configuration.DefaultSettingValueAttribute("Data Source=servername14;Initial Catalog=database14;User ID=username14;Password=password14")]
        public string ELSConnectionString {

# Json
{
    "connectionString" : "Data Source=servername16;Initial Catalog=database16;User ID=username16;Password=password16",
    "propertyA": "propertyA"
    "propertyB": "propertyB"
}

# Plain text
Data Source=(local);Initial Catalog=AdventureWorks;User ID=ab;Password= a1Pass@@11
    Modified: Data Source=(local);