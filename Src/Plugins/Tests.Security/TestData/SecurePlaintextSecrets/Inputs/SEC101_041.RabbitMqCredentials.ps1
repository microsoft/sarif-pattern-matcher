# Simple string
amqp://user:password@host/database1

# Simple string as value
"amqp://user:password@host/database2"

# Simple string as XML
<xml>amqps://user:password@host/database3</xml>

# Simple string with port
amqp://user:password@host:1234/database4

# Simple string with default vhost
"amqps://user:password@host:1234/"

# Name/value pairs
{ "name": "RABBITMQ_HOST", "value": "12.23.45.78" }, { "name": "RABBITMQ_PASSWORD", "value": "pass@word" }, { "name": "RABBITMQ_PORT", "value": "5672" }, { "name": "RABBITMQ_USERNAME", "value": "guest" },

# This is invalid and should not be captured
amqp://user:{{rabbitmq_password}}@host:1234/database4
amqp://user:password@host:1234 /database5
amqp://user:password@host:1234
amqp://id:secret @host/resource
amqp://id:secret
@host/resource
amqp://test":test@test/test