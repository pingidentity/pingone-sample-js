# OIDC Authentication Vanilla JS Sample Guide
The PingOne for Customers Authentication Sample is built on top of [OpenID Connect/OAuth 2 API endpoints](https://apidocs.pingidentity.com/pingone/customer/v1/api/auth/p1-a_Authorize/) to give 
you a basic overview how invoke P14C’s OIDC protocol to authenticate an existing user. This example shows you how to 
use the [PingOne for Customers auth.js library](auth.js) to login a user to your JavaScript application through the [implicit flow](https://openid.net/specs/openid-connect-implicit-1_0.html), 
where the user is redirected to the PingOne for Customers hosted login page.  
After the user authenticates it is redirected back to the application with an ID and access token.
For more information check this [OpenID Connect 1.0 Specifications](https://openid.net/developers/specs/)

## Prerequisites
You will need the following things:
 
- PingOne for Customers Account  - If you don’t have an existing one, please register it.
- An OpenID Connect Application, configured for Single-Page App (SPA) mode. Instructions for 
creating one can be found [here](TODO). Also make sure that it is enabled plus redirect URL's and 
access grants by scopes are properly set.
- At least one user in the same environment as the application (not assigned)

## Getting Started
If you haven't already done so, sign up for your PingOne for Customers account and create a new Single Page application in "Connections" tab of admin console. 

### Building the Source
```bash
git clone git@github.com:pingidentity/pingone-customers-sample-oidc.git .
cd vanilla-js
npm install
```

### Running the Sample
1. Find the following SPA application configuration information from the admin console to fulfill the next step with it: **environment id**, **client id** and **redirect uri**

2. Then create an OIDC client with all previously extracted data, by setting it directly or by calling `setConfig` method:
```js
authClient = new AuthOIDC({
  environment_id: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
  client_id: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
  redirect_uri: 'http://localhost:8080'
});
```
or
```js
let clientInfo = {
  environment_id: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
  client_id: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
  redirect_uri: 'http://localhost:8080'
}
authClient.setConfig(clientInfo);
```
, where
- `environment_id`: *Required*. Your application's Environment ID. You can find this value at your Application's Settings under 
**Configuration** tab from the admin console( extract `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` string that specifies the environment 128-bit universally unique identifier ([UUID](https://tools.ietf.org/html/rfc4122)) right from `https://auth.pingone
.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/as/authorize` 
*AUTHORIZATION URL* ). Or from the *Settings* main menu (*ENVIRONMENT ID* variable)
- `client_id`: *Required*. Your application's client UUID. You can also find this value at Application's Settings right under the 
Application name.
- `redirect_uri`: *Required*. The URL to which the PingOne will redirect the user's browser after authorization has been granted by 
the user. *REDIRECT URLS* values corresponds to this data. The Access and ID Token will be available in the hash fragment of this URL.
- `post_logout_redirect_uri`: *Optional*. The URL to which the browser is redirected after a logout has been performed. *LOGOUT URLS* values corresponds to this data. 

3. Initiate the OIDC client work in regard to user actions by calling `init` function. It returns a promise either with user data, retrieved from [UserInfo Endpoint](https://openid.net/specs/openid-connect-implicit-1_0.html#UserInfo),
 so you can display it right after, or rejected promise - if user is not logged in yet. :
```js
authClient.init()
  .then(data => {
        document.getElementById('first_name_title').innerHTML = data['given_name'];
        document.getElementById('last_name_title').innerHTML = data['family_name'];
        document.getElementById('userInfoView').innerHTML = '<br><b>User Details</b><br>'
            + authClient.formatIntoTable(data);
        document.getElementById('tokenInfoView').innerHTML = '<br><b>Token Details</b><br>'
            + authClient.showTokenClaimsInfo();
        displayViews();
      }
  )
  .catch(error => console.log(error));
```

Other functions you need to include are: 
+ the `signIn` function that redirects user to the Ping Identity Provider for authentication:

```js
authClient.signIn({
    scope: 'openid profile email address p1:read:self:user p1:update:self:user',
    response_type: 'token id_token'
  });
```

where
- `scope`:  standard OIDC or PingOne custom scopes, separated by a space which you want to request authorization for.
 [PingOne platform scopes](https://apidocs.pingidentity.com/pingone/customer/v1/api/auth/p1-a_AccessServices/#PingOne-platform-scopes-and-endpoint-operations) 
 are configured under "Access" tab in PingOne Admin Console
- `response_type`: The type of credentials returned in the response. For this flow you can either use token to get only an Access Token, id_token to get only an ID Token (if you don't plan on accessing an API), or id_token token to get both an ID Token and an Access Token.

+ `signOff` function that just initiates end user logout via the OIDC signoff endpoint and clears the browser session.
 
4. Then run
```bash
npm install && npm start
```
and browse to http://localhost:8080 

### Generate API documentation for Sample's JavaScript library
To generate documentation for auth.js:
```bash
./node_modules/.bin/jsdoc auth.js 
```
By default, the generated documentation is saved in a directory named out. You can use the --destination (-d) option 
to specify another directory.

### Developer Notes:
1. Following [Content Security Policy](https://www.owasp.org/index
.php/Content_Security_Policy_Cheat_Sheet#Refactoring_inline_code) all inline code preferable should be moved to a 
separate JavaScript file on production.
2. Values like `state` and `nonce` are used within [auth.js](auth.js) library to prevent CSRF and prevent token replay attacks respectively.
Your application sends the `state` (randomly generated value) when starting an authentication request and validate the received value when processing the response. If you receive a response with a state that does not match the initially generated value,
 then you may be the target of an attack because this is either a response for an unsolicited request or someone trying to forge the response.
 Your application also sends the `state` parameter to maintain state between the logout request and the callback to the endpoint specified by the `post_logout_redirect_uri query` parameter.
3. Make sure to open a browser tab that's not enforcing CORS. You can open another instance of chrome with disabled security (without closing other running chrome instances):
on Mac terminal:
```bash
open -n -a "Google Chrome" --args --user-data-dir=/tmp/temp_chrome_user_data_dir http://localhost:8080/ --disable-web-security
```
Otherwise you will see such error like *"No 'Access-Control-Allow-Origin' header is present on the requested resource"* on logout action.
4. A fetch() promise will reject with a TypeError when a network error is encountered or CORS is misconfigured on the server side. Instead, it will resolve normally (with ok status set to false), and it will only reject on network failure or if anything prevented the request from completing. 
See more about checking that the fetch was successful [here](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch#Checking_that_the_fetch_was_successful)
5. For simple styling [shoelace CSS library](https://shoelace.style/) was used, and [http-server](https://www.npmjs.com/package/http-server) - as a command-line http server.
