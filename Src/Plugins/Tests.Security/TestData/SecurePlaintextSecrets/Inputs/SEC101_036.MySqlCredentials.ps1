# This is a well-formed but invalid ADO MySql connection string - Implemented in MySqlConnectionStringAdo
Server=some-database-name.mysql.database.azure.com; Port=3306; Database=catalog_db; Uid=username@some-database-name; Pwd=password_1; SslMode=Preferred;
Port=3306; Server=some-database-name.mysql.database.azure.com; Database=catalog_db; Uid=username@some-database-name; Pwd=password_2; SslMode=Preferred;
Server=some-database-name.mysql.database.azure.com; Database=catalog_db; Uid=username@some-database-name; Pwd=password_3; SslMode=Preferred;Port=3306; 
Server=some-database-name.mysql.database.azure.com;Database=catalog_db; SslMode=Preferred; Pwd=password_4; Uid=username@some-database-name;

# This is a malformed and invalid ADO MySQL String. UiD should be in the form of <username>@<database-name>. This should be missed.
Server=some-database-name.mysql.database.azure.com; Port=3306; Database=catalog_db; Uid=username; Pwd=password_12; SslMode=Preferred;

# This is a well-formed but invalid JDBC MySql connection string - Implemented in MySqlConnectionStringPlainJdbc
String url ="jdbc:mysql://some-database-name.mysql.database.azure.com:3306/catalog_db?useSSL=true&requireSSL=false"; myDbConn = DriverManager.getConnection(url, "username@some-database-name", "PASSword_5");

# This is a well-formed but invalid Node.js MySql connection string - Unimplemented
var conn = mysql.createConnection({host: "some-database-name.mysql.database.azure.com", user: "username@some-database-name", password: password_6, database: catalog_db, port: 3306, ssl:{ca:fs.readFileSync({ca-cert filename})}});

# This is a well-formed but invalid PHP MySql connection string - Unimplemented
$con=mysqli_init(); mysqli_ssl_set($con, NULL, NULL, {ca-cert filename}, NULL, NULL); mysqli_real_connect($con, "some-database-name.mysql.database.azure.com", "username@some-database-name", password_7, catalog_db, 3306);

# This is a well-formed but invalid Python MySql connection string - Unimplemented
cnx = mysql.connector.connect(user="username@some-database-name", password=password_8, host="some-database-name.mysql.database.azure.com", port=3306, database=catalog_db, ssl_ca={ca-cert filename}, ssl_verify_cert=true)

# This is a well-formed but invalid Ruby MySql connection string - Unimplemented
client = Mysql2::Client.new(username: "username@some-database-name", password: password_9, database: catalog_db, host: "some-database-name.mysql.database.azure.com", port: 3306, sslca:{ca-cert filename}, sslverify:false, sslcipher:'AES256-SHA')

# This is a well-formed but invalid WebApp MySql connection string - Unimplemented
Database=catalog_db; Data Source=some-database-name.mysql.database.azure.com; User Id=username@some-database-name; Password=password_10

################ MariaDB shares the same connection string
# The following is copied from https://docs.microsoft.com/en-us/azure/mariadb/howto-connection-string

# ADO
## Configuration file - Implemented in MySqlConnectionStringAdo
Server=your-host; Port=3306; Database=your-database; Uid=username@servername; Pwd=your-password; SslMode=Preferred;

string connection = "Server=your-host; Port=3306; Database=your-database; Uid=username@servername; Pwd=password_11; SslMode=Preferred;";


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

################ ClearDB has similar connection strings
# The below taken from https://devcenter.heroku.com/articles/cleardb#configuring-your-ruby-application-to-use-cleardb

# Play! Framework - Implemented in MySqlConnectionStringPlainJdbc
String dbUrl = "jdbc:mysql://" + dbUri.getHost() + dbUri.getPath();
return DriverManager.getConnection(dbUrl, "cleardbusername1", "cleardb_PASSWORD1");

# Spring XML Configuration - Unimplemented
<property name="url" value="#{ 'jdbc:mysql://' + @dbUrl.getHost() + @dbUrl.getPath() }"/>
<property name="username" value="#{ @dbUrl.getUserInfo().split(':')[0] }"/>
<property name="password" value="#{ @dbUrl.getUserInfo().split(':')[1] }"/>

# Spring with Java configuration - Unimplemented
BasicDataSource basicDataSource = new BasicDataSource();
basicDataSource.setUrl("jdbc:mysql://" + dbUri.getHost() + dbUri.getPath());
basicDataSource.setUsername("username");
basicDataSource.setPassword("password");

# PHP - Unimplemented
$conn = new mysqli("server", "username", "password", "db");

# Python - Unimplemented
DATABASES['default'].update({
    'NAME': url.path[1:],
    'USER': url.username,
    'PASSWORD': url.password,
    'HOST': url.hostname,
    'PORT': url.port,
})


if url.scheme == 'mysql':
    DATABASES['default']['ENGINE'] = 'django.db.backends.mysql'