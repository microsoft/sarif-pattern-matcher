# Simple string
amqp://user:password@host/database1

# Simple string as value
"amqp://user:password@host/database2"

# Simple string as XML
<xml>amqps://user:password@host/database3</xml>

# Simple string with port
amqp://user:password@host:1234/database4

# This is invalid and should not be captured
amqp://user:password@host:1234 /database5
amqp://user:password@host:1234
amqp://id:secret @host/resource
amqp://id:secret
@host/resource