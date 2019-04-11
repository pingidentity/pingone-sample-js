# Introduction

This React sample demonstrates how to perform login actions that will initiate flow endpoint operations are used only to implement custom authentication UIs. 
OIDC/OAuth 2 requests initiate the flow and redirect the browser to the custom authentication UI (which is configured in the application through the application’s `loginPageUrl` property.)

- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Developer Notes](#developer-notes)
- [Available Scripts](#available-scripts)

# Prerequisites 
You will need the following things:

- PingOne for Customers Account - If you don’t have an existing one, please register it.
- An new [Application](https://documentation.pingidentity.com/pingone/p14cAdminGuide/index.shtml#p1_t_addApplication.html), configured for Single-Page App (SPA) or Native mode. Also make sure that it is enabled plus redirect, sign off URL's and access grants by scopes are properly set.
- Specify custom login page URL for the application in __SIGNON URL__ textbox of P14C admin console. 

# Getting Started

1. Clone a source code
`git clone git@github.com:pingidentity/pingone-customers-sample-custom-signon.git . `
2. Update [config.js](./src/config.js) with your application data extracted from P14C admin console:
    - `environment_id`: *Required*. Your application's Environment ID. You can find this value at your Application's Settings under 
    **Configuration** tab from the admin console( extract `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` string that specifies the environment 128-bit universally unique identifier ([UUID](https://tools.ietf.org/html/rfc4122)) right from `https://auth.pingone
    .com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/as/authorize` 
    *AUTHORIZATION URL* ). Or from the *Settings* main menu (*ENVIRONMENT ID* variable)
    - `client_id`: *Required*. Your application's client UUID. You can also find this value at Application's Settings right under the 
    Application name.
    - `clientSecret`: A string that specifies the the application’s client secret. This property is required only if the application’s `tokenEndpointAuthMethod` property is set to `CLIENT_SECRET_POST`.
    - `responseType`: A string that specifies the code or token type returned by an authorization request. Options are `token`, `id_token`, and `code`. The value **MUST** be the `code` for requesting an authorization code flow, `id_token token` for the implicit flow, or `code id_token` for hybrid flow(a scenario when you can have a long lived session in your application and get tokens back immediately from the authorization endpoint).
    For more variants please check [Definitions of Multiple-Valued Response Type Combinations](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations) topic.
    - `grantType`: A string that specifies the grant type of the token request. Options are `authorization_code`, `implicit`(is set by default), and `client_credentials`. So, if you have `responseType=code`, then define `redirectUri=authorization_code`.
    - `redirectUri`: *Required*. The URL to which the PingOne will redirect the user's browser after authorization has been granted by the user. *REDIRECT URLS* values corresponds to this data. The Access and ID Token will be available in the hash fragment of this URL. 
    For simplicity this sample has it hardcoded as `http://localhost:3000/callback`, where `/callback` is handled by [callback react component](src/components/home.jsx)
    - `logoutRedirectUri`: The URL to which the browser is redirected after a logout has been performed. *SIGNOFF URLS* values corresponds to this data.
    - `scope`: A string that specifies permissions that determine the resources that the application can access. This parameter is not required, but it is needed to specify accessible resources.
    - `tokenEndpointAuthMethod`: A string that specifies the client authentication methods supported by the token endpoint. This is a required property. Options are `none`, `client_secret_basic`, and `client_secret_post`.
3. Build a project by `npm install` or `yarn install`
4. Start an application by `npm start` or `yarn start`

## Application, grant and response type relationships
The following table shows the relationships between the application type attribute and the default `grantTypes`, `response_type`, and `tokenEndpointAuthMethod` attributes.

|    Application type   |    Grant type   |    Response type   |    Token endpoint authentication method   |
| --------------------- |   ------------- |------------------- |------------------------------------------ |
| Non-interactive	| client_credentials	| token	| client_secret_basic| 
| Native	| authorization_code, implicit	| token, id_token, code	| none| 
| Web	| authorization_code	| code	| client_secret_basic| 
| Single-page	| implicit	| token, id_token	| none| 


## PingOne for Customers API used in this sample
### Authentication API:
|    Endpoint   |    Description   |
| ------------- |------------- |
| [`POST /{environmentId}/as/authorize`](https://apidocs.pingidentity.com/pingone/customer/v1/api/auth/p1-a_Authorize/#Authorization-request-with-a-code-grant) <br>  `prompt=login` parameter is used by default  | Authorization request with a code or implicit grant type.|
| [`POST /{environmentId}/as/token`](https://apidocs.pingidentity.com/pingone/customer/v1/api/auth/p1-a_Authorize/#Obtain-an-access-token)  | Obtain an access token in authorization grant case|
| [`GET /{environmentID}/as/signoff?id_token_hint={idToken}`](https://apidocs.pingidentity.com/pingone/customer/v1/api/auth/p1-a_Authorize/#Get-signoff) <br> if `post_logout_redirect_uri` parameter is provided and it does not match one of the `postLogoutRedirectUri` values of your application in the specified environment - it would be handled as an unpredictable error.  | Obtain an access token in authorization grant case|

**Note:** For any application type (except non-interactive), you can specify either `none`, `client_secret_basic`, or `client_secret_post` as the `tokenEndpointAuthMethod` attribute value. Non-interactive applications use the `client_credentials` grant type, which does not support a `tokenEndpointAuthMethod` value of none.

# Developer Notes

This project was bootstrapped with [Create React App](https://github.com/facebook/create-react-app). So you don’t need to install or configure tools like Webpack or Babel.
They are preconfigured and hidden so that you can focus on the code.

1. In case you want to experience more OIDC and other [PingOne for Customers Management APIs](https://apidocs.pingidentity.com/pingone/customer/v1/api/man/) without enforcing CORS, you can open another instance of chrome with disabled security (without closing other running chrome instances):
on Mac terminal:
```bash
open -n -a "Google Chrome" --args --user-data-dir=/tmp/temp_chrome_user_data_dir http://localhost:3000/ --disable-web-security
```
Otherwise you will see such error like *"No 'Access-Control-Allow-Origin' header is present on the requested resource"* on some actions.


2. `componentDidMount` is only called once in the lifecycle of any component, re-render will not reinitialize the component. `componentDidUpdate` will be called where you can manage your logic.
3. Sample doesn't use a sophisticated persistent layer for OAuth2 tokens, thereby a browser `session storage` was used as a cache (so you don't loose them once the browser tab is closed or refreshed).  [sessionStorage](https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage) is similar to [localStorage](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage); the only difference is while data stored in `localStorage` has no expiration time, data stored in `sessionStorage` gets cleared when the page session ends. A page session lasts for as long as the browser is open and survives over page reloads and restores.
If you are looking for more advanced local storage solutions, you can checkout [store.js](https://github.com/marcuswestin/store.js/), [cross-storage](https://github.com/zendesk/cross-storage) or similar solutions. 
4. For the development server port 8080 is used, that is specified in [package.json](package.json) `“start”` script as follows: ` "start": “PORT=8080 react-scripts start",`


# Available Scripts

In the project directory, you can run:

### `npm start` or `yarn start`

Runs the app in the development mode.<br>
Open [http://localhost:8080](http://localhost:8080) to view it in the browser. If you see CORS related issues like **"Origin is not allowed by Access-Control-Allow-Origin"**, please open another instance of your browser with disabled security.
If you are using Chrome on Mac OS, then start it as:
```bash
open -n -a "Google Chrome" --args --user-data-dir=/tmp/temp_chrome_user_data_dir http://localhost:8080/ --disable-web-security
```

The page will reload if you make edits.<br>
You will also see any lint errors in the console.

### `npm test`  or `yarn test`

Launches the test runner in the interactive watch mode.<br>
See the section about [running tests](https://facebook.github.io/create-react-app/docs/running-tests) for more information.

### `npm run build`  or `yarn build`

Builds the app for production to the `build` folder.<br>
It correctly bundles React in production mode and optimizes the build for the best performance.

The build is minified and the filenames include the hashes.<br>
Your app is ready to be deployed!

See the section about [deployment](https://facebook.github.io/create-react-app/docs/deployment) for more information.

### `npm run eject`

**Note: this is a one-way operation. Once you `eject`, you can’t go back!**

If you aren’t satisfied with the build tool and configuration choices, you can `eject` at any time. This command will remove the single build dependency from your project.

Instead, it will copy all the configuration files and the transitive dependencies (Webpack, Babel, ESLint, etc) right into your project so you have full control over them. All of the commands except `eject` will still work, but they will point to the copied scripts so you can tweak them. At this point you’re on your own.

You don’t have to ever use `eject`. The curated feature set is suitable for small and middle deployments, and you shouldn’t feel obligated to use this feature. However we understand that this tool wouldn’t be useful if you couldn’t customize it when you are ready for it.

## Learn More

You can learn more in the [Create React App documentation](https://facebook.github.io/create-react-app/docs/getting-started).

To learn React, check out the [React documentation](https://reactjs.org/).

### Code Splitting

This section has moved here: https://facebook.github.io/create-react-app/docs/code-splitting

### Analyzing the Bundle Size

This section has moved here: https://facebook.github.io/create-react-app/docs/analyzing-the-bundle-size

### Making a Progressive Web App

This section has moved here: https://facebook.github.io/create-react-app/docs/making-a-progressive-web-app

### Advanced Configuration

This section has moved here: https://facebook.github.io/create-react-app/docs/advanced-configuration

### Deployment

This section has moved here: https://facebook.github.io/create-react-app/docs/deployment

### `npm run build` fails to minify

This section has moved here: https://facebook.github.io/create-react-app/docs/troubleshooting#npm-run-build-fails-to-minify
