# RestClient example
var client = new RestClient("https://example.com");
var request = new RestRequest(Method.GET);
request.AddHeader("Authorization", "Basic SomeAuthorizationKey0123456");

var client = new RestClient("https://example.com?some=parameters&that=should&appear=inresults")
var request = new RestRequest(Method.GET);
request.AddHeader("Authorization", "Basic SomeAuthorizationKey0123456");

# This should not get caught, since it will drop the last slash
# and would be equal to the first example.
var client = new RestClient("https://example.com/")
var request = new RestRequest(Method.GET);
request.AddHeader("Authorization", "Basic SomeAuthorizationKey0123456");

# cURL
curl --location --request GET 'https://example.com' \
--header 'Authorization: Basic SomeAuthorizationKey0123456=' \