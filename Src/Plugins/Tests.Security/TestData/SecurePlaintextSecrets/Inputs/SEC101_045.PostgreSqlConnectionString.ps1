# ADO.NET
# Using Npgsql
# Currently caught
Host=my_host;Database=my_db;Username=my_user;Password=my_pw
############### The rest of these patterns are not implemented!!
Username=mylogin;Password=mypass;Database=mydatabase
Password=mypass;Database=mydatabase;Username=mylogin;

# JDBC
# Dream validation will catch the first method of connection string declaration
# but it's not expected.
String url = "jdbc:postgresql://localhost/test";
Properties props = new Properties();
props.setProperty("user","fred");
props.setProperty("password","secret");
props.setProperty("ssl","true");
Connection conn = DriverManager.getConnection(url, props);

jdbc:postgresql://localhost/test?user=fred&password=secret&ssl=true

# Node.js
# Using node-postgresql
# Node uses environment variables by default, which would be declared something like the first method
PGUSER=dbuser \
PGHOST=database.server.com \
PGPASSWORD=secretpassword \
PGDATABASE=mydb \
PGPORT=3211 \
node script.js

const pool = new Pool({
  user: 'dbuser',
  host: 'database.server.com',
  database: 'mydb',
  password: 'secretpassword',
  port: 3211,
})

const pool = new Pool({ user: 'dbuser', host: 'database.server.com', database: 'mydb', password: 'secretpassword', port: 3211,})

const client = new Client({
  user: 'dbuser',
  host: 'database.server.com',
  database: 'mydb',
  password: 'secretpassword',
  port: 3211,
})

const client = new Client({ user: 'dbuser', host: 'database.server.com', database: 'mydb', password: 'secretpassword', port: 3211,})

# PHP
$dbconn3 = pg_connect("host=sheep port=5432 dbname=mary user=lamb password=foo");
$conn_string = "host=sheep port=5432 dbname=test user=lamb password=bar";
$dbconn4 = pg_connect($conn_string);

# Python
# Using psycopg2 
conn = psycopg2.connect("dbname=suppliers user=postgres password=postgres")
conn = psycopg2.connect(
    host="localhost",
    database="suppliers",
    user="postgres",
    password="Abcd1234")

conn = psycopg2.connect(host="localhost",database="suppliers",user="postgres",password="Abcd1234")

# Ruby
# Using libpq 
con = PG.connect :dbname => 'testdb', :user => 'janbodnar', :password => 'pswd37'