# This is a well-formed but invalid ADO MySql connection string
Server=some-database-name.mysql.database.azure.com; Port=3306; Database=catalog_db; Uid=username@some-database-name; Pwd=password_1; SslMode=Preferred;
Port=3306; Server=some-database-name.mysql.database.azure.com; Database=catalog_db; Uid=username@some-database-name; Pwd=password_2; SslMode=Preferred;
Server=some-database-name.mysql.database.azure.com; Database=catalog_db; Uid=username@some-database-name; Pwd=password_3; SslMode=Preferred;Port=3306; 
Server=some-database-name.mysql.database.azure.com;Database=catalog_db; SslMode=Preferred; Pwd=password_4; Uid=username@some-database-name;

# This is a well-formed but invalid JDBC MySql connection string
String url ="jdbc:mysql://some-database-name.mysql.database.azure.com:3306/catalog_db?useSSL=true&requireSSL=false"; myDbConn = DriverManager.getConnection(url, "username@some-database-name", password_5);

# This is a well-formed but invalid Node.js MySql connection string
var conn = mysql.createConnection({host: "some-database-name.mysql.database.azure.com", user: "username@some-database-name", password: password_6, database: catalog_db, port: 3306, ssl:{ca:fs.readFileSync({ca-cert filename})}});

# This is a well-formed but invalid PHP MySql connection string
$con=mysqli_init(); mysqli_ssl_set($con, NULL, NULL, {ca-cert filename}, NULL, NULL); mysqli_real_connect($con, "some-database-name.mysql.database.azure.com", "username@some-database-name", password_7, catalog_db, 3306);

# This is a well-formed but invalid Python MySql connection string
cnx = mysql.connector.connect(user="username@some-database-name", password=password_8, host="some-database-name.mysql.database.azure.com", port=3306, database=catalog_db, ssl_ca={ca-cert filename}, ssl_verify_cert=true)

# This is a well-formed but invalid Ruby MySql connection string
client = Mysql2::Client.new(username: "username@some-database-name", password: password_9, database: catalog_db, host: "some-database-name.mysql.database.azure.com", port: 3306, sslca:{ca-cert filename}, sslverify:false, sslcipher:'AES256-SHA')

# This is a well-formed but invalid WebApp MySql connection string
Database=catalog_db; Data Source=some-database-name.mysql.database.azure.com; User Id=username@some-database-name; Password=password_10

################ MariaDB shares the same connection string
# The following is copied from https://docs.microsoft.com/en-us/azure/mariadb/howto-connection-string

# ADO
## Configuration file - Implemented
Server=your-host; Port=3306; Database=your-database; Uid=username@servername; Pwd=your-password; SslMode=Preferred;

## C# code - Unimplemented
Server= "mydemoserver.mariadb.database.azure.com"; Port=3306; Database= "wpdb"; Uid= "WPAdmin@mydemoserver"; Pwd="mypassword!2"; SslMode=Required;

# JDBC - Unimplemented
String url ="jdbc:mariadb://{your_host}:3306/{your_database}?useSSL=true&trustServerCertificate=true"; myDbConn = DriverManager.getConnection(url, "{username@servername}", {your_password_2});

# Node.js - Unimplemented
var conn = mysql.createConnection({host: "{your_host}", user: "{your_username}", password: {your_password}, database: {your_database}, port: 3306, ssl:{ca:fs.readFileSync({ca-cert filename})}});

# ODBC - Unimplemented
DRIVER={MARIADB ODBC 3.0 Driver}; Server="{your_host}"; Port=3306; Database={your_database}; Uid="{username@servername}"; Pwd={your_password}; sslca={ca-cert filename}; sslverify=1;

# PHP - Unimplemented
$con=mysqli_init(); mysqli_ssl_set($con, NULL, NULL, {ca-cert filename}, NULL, NULL); mysqli_real_connect($con, "{your_host}", "{username@servername}", {your_password}, {your_database}, 3306);

# Python - Unimplemented
cnx = mysql.connector.connect(user="{username@servername}", password={your_password}, host="{your_host}", port=3306, database={your_database}, ssl_ca={ca-cert filename}, ssl_verify_cert=true)

# Ruby - Unimplemented
client = Mysql2::Client.new(username: "{username@servername}", password: {your_password}, database: {your_database}, host: "{your_host}", port: 3306, sslca:{ca-cert filename}, sslverify:false, sslcipher:'AES256-SHA')