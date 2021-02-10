# ADO.NET
# Using Npgsql
# Currently caught
<add name="BlogDbContext" connectionString="host=my_host;Port=5555;Database=my_db;Username=my_user;Password=my_pw_1"> # host not capitalized, optional properties in the middle
<add name="BlogDbContext" connectionString="host=my_host;Database=my_db;Username=my_user;Password=my_pw_2;Port=5555"> # optional properties in the middle and at the end
<add name="BlogDbContext" connectionString="Host=my_host;Port=5555;UsErname=my_user;Password=my_pw_3"> # weird capitalization on UsErname
<add name="BlogDbContext" connectionString="Password=my_pw_4;Host=my_host;Port=5555;Username=my_user;Pooling=true"> # weird order, unnecessary property at the end
<add name="BlogDbContext" connectionString="Port=5555;Password=my_pw_5;Connection Pruning Interval=doodle;Host=my_host;Username=my_user;Pooling=true"> # begin with optional property
<add name="BlogDbContext" connectionString="Port=5555;Password=my_pw_6;Connection Pruning Interval=doodle;Host=my_host;Username=my_user;Pooling=true;Port=5555"> # redundant optional property at beginning and end
<add name="BlogDbContext" connectionString="Database=my_db;Port=5555;Password=my_pw_7;Connection Pruning Interval=doodle;Host=my_host;Username=my_user;Pooling=true; Port=5555"> # space preceeding optional property

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
PGPASSWORD=secretpassword_1 \
PGDATABASE=mydb \
PGPORT=3211 \
node script.js

const pool = new Pool({
  user: 'dbuser',
  host: 'database.server.com',
  database: 'mydb',
  password: 'secretpassword_2',
  port: 3211,
})

const pool = new Pool({ user: 'dbuser', host: 'database.server.com', database: 'mydb', password: 'secretpassword_3', port: 3211,})

const client = new Client({
  user: 'dbuser',
  host: 'database.server.com',
  database: 'mydb',
  password: 'secretpassword_4',
  port: 3211,
})

const client = new Client({ user: 'dbuser', host: 'database.server.com', database: 'mydb', password: 'secretpassword_5', port: 3211,})

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

conn = psycopg2.connect(host="localhost",database="suppliers",user="postgres",password="Abcd12345")

# Ruby
# Using libpq 
con = PG.connect :dbname => 'testdb', :user => 'janbodnar', :password => 'pswd37'