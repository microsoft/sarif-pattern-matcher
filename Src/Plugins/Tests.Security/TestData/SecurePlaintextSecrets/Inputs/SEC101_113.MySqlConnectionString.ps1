# This is a well-formed but invalid ADO MySql connection string
Server=some-database-name.mysql.database.azure.com; Port=3306; Database=catalog_db; Uid=username@some-database-name; Pwd=password; SslMode=Preferred;

# This is a well-formed but invalid JDBC MySql connection string
String url ="jdbc:mysql://some-database-name.mysql.database.azure.com:3306/catalog_db?useSSL=true&requireSSL=false"; myDbConn = DriverManager.getConnection(url, "username@some-database-name", password);

# This is a well-formed but invalid Node.js MySql connection string
var conn = mysql.createConnection({host: "some-database-name.mysql.database.azure.com", user: "username@some-database-name", password: password, database: catalog_db, port: 3306, ssl:{ca:fs.readFileSync({ca-cert filename})}});

# This is a well-formed but invalid PHP MySql connection string
$con=mysqli_init(); mysqli_ssl_set($con, NULL, NULL, {ca-cert filename}, NULL, NULL); mysqli_real_connect($con, "some-database-name.mysql.database.azure.com", "username@some-database-name", password, catalog_db, 3306);

# This is a well-formed but invalid Python MySql connection string
cnx = mysql.connector.connect(user="username@some-database-name", password=password, host="some-database-name.mysql.database.azure.com", port=3306, database=catalog_db, ssl_ca={ca-cert filename}, ssl_verify_cert=true)

# This is a well-formed but invalid Ruby MySql connection string
client = Mysql2::Client.new(username: "username@some-database-name", password: password, database: catalog_db, host: "some-database-name.mysql.database.azure.com", port: 3306, sslca:{ca-cert filename}, sslverify:false, sslcipher:'AES256-SHA')

# This is a well-formed but invalid WebApp MySql connection string
Database=catalog_db; Data Source=some-database-name.mysql.database.azure.com; User Id=username@some-database-name; Password=password
