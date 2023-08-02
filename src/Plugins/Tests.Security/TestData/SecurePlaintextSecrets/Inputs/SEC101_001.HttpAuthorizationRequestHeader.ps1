# RestClient example
var client = new RestClient("https://example.com");
var request = new RestRequest(Method.GET);
request.AddHeader("Authorization", "Basic SomeAuthorizationKey1111111");

var client = new RestClient("https://example.com?some=parameters&that=should&appear=inresults")
var request = new RestRequest(Method.GET);
request.AddHeader("Authorization", "Basic SomeAuthorizationKey2222222");

# cURL
curl --location --request GET 'https://example.com' \
--header 'Authorization: Basic SomeAuthorizationKey3333333=' \

# This should not get caught, since it will drop the last slash
# and would be equal to the first example.
var client = new RestClient("https://example.com/")
var request = new RestRequest(Method.GET);
request.AddHeader("Authorization", "Basic SomeAuthorizationKey4444444");

# This should not get caught, since it would surpass the length
# between url and authorization
var client = new RestClient("https://example.com/")
var request = new RestRequest(Method.GET);
var text = "more text to surpass the size.";
request.AddHeader("Authorization", "Basic SomeAuthorizationKey5555555");


<protocol>
GET http://we.want.that.site.com/16 HTTP/1.1
Host: we.want.that.site.com
Proxy-Authorization: Basic 6666666b29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29uZw==
Accept: */*
Proxy-Connection: Keep-Alive

 

</protocol>
</verify>