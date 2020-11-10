# OIDC Authentication JavaScript Sample Guide
The PingOne Authentication Sample is built on top of [OpenID Connect/OAuth 2 API endpoints](https://apidocs.pingidentity.com/pingone/platform/v1/api/) to give 
you a basic overview how invoke PingOne’s OIDC protocol to authenticate an existing user. 
This example shows you how to 
use [@ping-identity/p14c-js-sdk-auth](https://www.npmjs.com/package/@ping-identity/p14c-js-sdk-auth) library to login a user to your JavaScript application through the [implicit flow](https://openid.net/specs/openid-connect-implicit-1_0.html), 
where the user is redirected to the PingOne hosted login page.  
After the successful authentication it is redirected back to the application with an ID and access token.
For more information check out [OpenID Connect 1.0 Specifications](https://openid.net/developers/specs/).


#### OAuth 2.0 vs OIDC
**OAuth 2.0** is not an authentication protocol, but OIDC is. <br />
**OAuth 2.0** is about giving this delegated access for use in situations where the user is not present on the connection between the client and the resource being accessed.
The client application then becomes a consumer of the identity API. One major benefit of building authentication on top of authorization in this way is that it allows for management of end-user consent, which is very important in cross-domain identity federation at internet scale.

**OIDC** tells an application who the current user is and whether or not they're present.

## Tutorial Video

A tutorial video detailing the implementation of this sample application is available on YouTube: [https://youtu.be/TBA5VTfnsSE](https://youtu.be/TBA5VTfnsSE)

## Prerequisites
You will need the following things:
 
- PingOne Account  - If you don’t have an existing one, please register it.
- An OpenID Connect Application, configured for Single-Page App (SPA) mode. Instructions for 
creating one can be found [here](https://developer.pingidentity.com/content/p14c/en/signup.html). Also make sure that it is enabled plus redirect URL's and 
access grants by scopes are properly set.
- At least one user in the same environment as the application (not assigned)
- To have installed [Node.js](https://nodejs.org/en/download/)

## Getting Started
If you haven't already done so, sign up for your PingOne account and create a new Single Page application in "Connections" tab of admin console. You can begin a trial at [https://www.pingidentity.com/en/trials.html](https://www.pingidentity.com/en/trials.html)

### Building the Sample
```bash
git clone git@github.com:pingidentity/pingone-sample-oidc.git .
npm install && npm run-script build
```

### Running the Sample

1. Find the following SPA application configuration information from the admin console to fulfill the next step with it: **environment id**, **client id** and **redirect uri**
1. Update `PingOneAuthClient` with all previously extracted data:
```js
const authClient = new PingOneAuthClient({
  environmentId: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
  clientId: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
  redirectUri: 'http://localhost:8080',
  postLogoutRedirectUri: 'http://localhost:8080',
  scopes: ['openid','profile', 'email', 'address'],
  responseType: ['token', 'id_token'],
  pkce: false
});
```
, where
- `environmentId`: **Required**. Your application's Environment ID. You can find this value at your Application's Settings under 
**Configuration** tab from the admin console( extract `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` string that specifies the environment 128-bit universally unique identifier ([UUID](https://tools.ietf.org/html/rfc4122)) right from `https://auth.pingone
.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/as/authorize` 
*AUTHORIZATION URL* ). Or from the *Settings* main menu (*ENVIRONMENT ID* variable)

- `clientId`: **Required**. Your application's client UUID. You can also find this value at Application's Settings right under the 
Application name.

- `redirectUri`: **Required**. The URL to which the PingOne will redirect the user's browser after authorization has been granted by 
the user. *REDIRECT URLS* values corresponds to this data. The Access and ID Token will be available in the hash fragment of this URL.

- `postLogoutRedirectUri`: **Optional**.. The URL to which the browser is redirected after a logout has been performed. *SIGNOFF URLS* values corresponds to this data. 

- `scopes`:  **Optional**. standard OIDC or PingOne custom scopes, separated by a space which you want to request authorization for.
 [PingOne platform scopes](https://apidocs.pingidentity.com/pingone/platform/v1/api/#access-services-through-scopes-and-roles) 
 are configured under "Access" tab in PingOne Admin Console. Default value: `["openid"]`

- `responseType`: The type of credentials returned in the response: `token` - to get only an Access Token, `id_token` - to get only an ID Token (if you don't plan on accessing an API).

- `responseMode` :  **Optional**.  A string that specifies the mechanism for returning authorization response parameters from the authorization endpoint. If set to `pi.flow` value than the redirect_uri parameter is not required and authorization response parameters are encoded as a JSON object wrapped in a flow response and returned directly to the client with a 200 status.
Default value: not set. 

- `responseType` : **Optional**. An array of `["token", "id_token", "code"]`. Default value: `["token", "id_token"]`.

- `storage` :  **Optional**. Tokens storage type. Possible values are [`localStorage`](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage), [`sessionStorage`](https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage), `cookieStorage`, `memoryStorage`. Default value: `localStorage`.
Window `localStorage` - data is stored and saved across browser sessions without expiration time. 
Window `sessionStorage` - data gets cleared when the page session ends(when the page is closed). 
`cookieStorage`, `memoryStorage`.

- `tokenRenew` :  **Optional**. Renew expired token either with refresh token (if `useRefreshTokens=true`) or using a hidden iframe. Default value: `true`.

- `useRefreshTokens`: **Optional**. Use refresh token to exchange for new access tokens instead of using a hidden iframe and `/oauth/token` endpoint call.   

- `pkce`: **Optional**. Use Authorization Code with Proof Key for Code Exchange (PKCE) flow for token retrieval.

- `cookies: {
           secure: true,
           sameSite: 'none'
       }` : **Optional**. Cookies storage configuration. 
       [`SameSite`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) attribute allows you to declare if your cookie should be restricted to a first-party or same-site context.

- `max_age`: : **Optional**.  Integer that specifies the maximum amount of time allowed since the user last authenticated. If the `max_age` value is exceeded, the user must re-authenticate.

- `acr_values` : **Optional**. String  that designates whether the authentication request includes specified sign-on policies. Sign-on policy names should be listed in order of preference, and they must be assigned to the application. For more information, see [Sign-on policies](https://apidocs.pingidentity.com/pingone/platform/v1/api/#sign-on-policies)

- `API_URI` : **Optional**. PingOne API base endpoint. Default value: `https://api.pingone.com`

- `AUTH_URI` : **Optional**. PingOne Authentication base endpoint. Default value:`https://auth.pingone.com`

1. Run
```bash
npm start
```
and browse to http://localhost:8080 

### Sample Code Explanation
These steps below describes on a high level what functionality is being shown in this code example.

1. Added the latest version of [@ping-identity/p14c-js-sdk-auth](https://www.npmjs.com/package/@ping-identity/p14c-js-sdk-auth) npm module to your [package.json](package.json):
```
"dependencies": {
    "@ping-identity/p14c-js-sdk-auth": "1.0.0-pre.1"
  }
``` 
1. Parsed current URL and got possible (id and access) tokens after user is redirected back to this application.
```
authClient.parseRedirectUrl()
```
1. Got user data from [UserInfo Endpoint](https://openid.net/specs/openid-connect-implicit-1_0.html#UserInfo),
 after user successfully logged in :
```js
authClient.getUserInfo()
  .then(user => {
        document.getElementById('first_name_title').innerHTML = user['given_name'];
        document.getElementById('last_name_title').innerHTML = user['family_name'];
        document.getElementById('userInfoView').innerHTML = '<br><b>User Details</b><br>'
            + jsonIntoHtmlTable(user);
      });
```

Other functions included here: 
- `authClient.signIn();` function that redirects user to the Ping Identity Provider for authentication:
- `authClient.signOut()` function that just initiates end user logout via the OIDC signoff endpoint and clears the browser session.
 

### Developer Notes:
1. Following [Content Security Policy](https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet#Refactoring_inline_code) all inline code preferable should be moved to a 
separate JavaScript file on production.
1. Values like `state` and `nonce` are used within [@ping-identity/p14c-js-sdk-auth](https://www.npmjs.com/package/@ping-identity/p14c-js-sdk-auth) library to prevent CSRF and token replay attacks respectively.
Your application sends the `state` (randomly generated value) when starting an authentication request and validate the received value when processing the response. If you receive a response with a state that does not match the initially generated value,
 then you may be the target of an attack because this is either a response for an unsolicited request or someone trying to forge the response.
 Your application also sends the `state` parameter to maintain state between the logout request and the callback to the endpoint specified by the `post_logout_redirectUri query` parameter.
1. For styling the [shoelace CSS library](https://shoelace.style/) was used, and [http-server](https://www.npmjs.com/package/http-server) - as a command-line http server.
