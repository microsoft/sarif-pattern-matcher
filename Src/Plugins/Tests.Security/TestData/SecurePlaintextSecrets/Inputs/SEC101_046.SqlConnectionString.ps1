# This is a well-formed but invalid ADO sql connection string
server=tcp:some-database-name.database.windows.net,1433;Initial Catalog=catalog-db;Persist Security Info=False;User ID=username;Password=password;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;
Initial Catalog=catalog-db;Persist Security Info=False;Password=password;MultipleActiveResultSets=False;Encrypt=True;User ID=username;TrustServerCertificate=False;Connection Timeout=30;server=tcp:some-database-name.database.windows.net,1433;
Data Source=0.0.0.0,1433;Network Library=DBMSSOCN;Initial Catalog=catalog-db;User ID=username;Password=password;

# This is a well-formed but invalid ODBC sql connection string
jdbc:sqlserver://some-database-name.database.windows.net:1433;database=tse-internal-spam-testing;user=username@some-database-name;password=password;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;

# This is a well-formed but invalid JDBC sql connection string
Driver={ODBC Driver 13 for SQL Server};Server=tcp:some-database-name.database.windows.net,1433;Database=tse-internal-spam-testing;Uid=username;Pwd=password;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;

# This is a well-formed but invalid PHP SQL connection string
new PDO("sqlsrv:server = tcp:some-database-name.database.windows.net,1433; Database = some-database-name", "username", "password");
