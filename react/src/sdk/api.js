/**
 * PingOne authentication flow and OpenID Connect/OAuth 2 protocol API.
 *
 * Contains functions that correspond to steps needed to make it through a PingOne authentication flow.
 * Each function corresponds with an action the UI needs to take and call function(s) from actions.js
 */
import _ from "lodash";
import request from "superagent";
import config from "../config";


/******************************************************************************
 *         OAuth 2/OpenID Connect Protocol API
 ******************************************************************************/

/**
 *  Authorize the client
 *
 * @param environmentId a string that specifies the environment’s UUID.
 * @param responseType a string that specifies the code or token type returned by an authorization request. Options are token, id_token, and code. Default values is "token id_token". This is a required property.
 * @param clientId a string that specifies the application’s UUID.
 * @param redirectUri a string that specifies the URL that specifies the return entry point of the application. This is a required property.
 * @param scope a string that specifies permissions that determine the resources that the application can access. This parameter is not required, but it is needed to specify accessible resources.
 * @param state a string that specifies an optional parameter that is used to maintain state between the logout request and the callback to the endpoint specified by the post_logout_redirect_uri query parameter.
 * @param nonce a string that is used to associate a client session with an ID token, and to mitigate replay attacks. The value is passed through unmodified from the authentication request to the ID token.
 * @param prompt a string that specifies whether the user is prompted to login for re-authentication. The prompt parameter can be used as a way to check for existing authentication, verifying that the user is still present for the current session. For prompt=none, the user is never prompted to login to re-authenticate, which can result in an error if authentication is required. For prompt=login, if time since last login is greater than the max-age, then the current session is stashed away in the flow state and treated in the flow as if there was no previous existing session. When the flow completes, if the flow’s user is the same as the user from the stashed away session, the stashed away session is updated with the new flow data and persisted (preserving the existing session ID). If the flow’s user is not the same as the user from the stashed away session, the stashed away session is deleted (logout) and the new session is persisted.
 * @param maxAge a string that specifies the maximum amount of time allowed since the user last authenticated. If the max_age value is exceeded, the user must re-authenticate.
 * @param acr_values an optional parameter that designates whether the authentication request includes steps for a single-factor or multi-factor authentication flow. This parameter maps to the name of a sign-on policy that must be assigned to the application. For more information, see Sign-on policies.
 * @returns {Promise<T | never>}
 */
const authorize = (environmentId, responseType='token id_token', clientId, redirectUri, scope,
    state, nonce, prompt = 'login', maxAge, acrValues = null) => {
  let authUrl = `${getBaseApiUrl(
      true)}/${environmentId}/as/authorize?` +
      `response_type=${responseType}&client_id=${clientId}&redirect_uri=${redirectUri}&prompt=${prompt}` +
      (scope ? `&scope=${scope}` : '') +
      (maxAge ? `&max_age=${maxAge}` : '') +
      (acrValues ? `&acr_values=${acrValues}` : '') +
      (state ? `&state=${state}` : '') +
      (nonce ? `&nonce=${nonce}` : '');
  window.location.replace(authUrl);

};

/**
 * Ends the user session associated with the given ID token.
 * @param environmentId - a required attribute that specifies environment id
 * @param logoutRedirectUri - a string that specifies an optional parameter that specifies the URL to which the browser is redirected after a logout has been performed.
 * @param token  - a required attribute that specifies the ID token passed to the logout endpoint as a hint about the user’s current authenticated session.
 * @param state - a string that specifies an optional parameter that is used to maintain state between the logout request and the callback to the endpoint specified by the logoutRedirectUri query parameter
 * @see {@link https://openid.net/specs/openid-connect-session-1_0.html#RPLogout|RP-Initiated Logout}
 */
const signOff = (environmentId, logoutRedirectUri, token, state) => {
  let singOffUrl = `${getBaseApiUrl(
      true)}/${environmentId}/as/signoff?id_token_hint=${token}`;
  if (logoutRedirectUri && state) {
    singOffUrl = singOffUrl.concat(
        `&post_logout_redirect_uri=${logoutRedirectUri}&state=${state}`);
  }
  window.location.assign(singOffUrl);
};

/**
 * Get claims about the authenticated end user from UserInfo Endpoint (OAuth 2.0 protected resource)
 * A userinfo authorization request is used with applications associated with the openid resource.
 * @param environmentId a string that specifies the environment’s UUID.
 * @param token access token
 */
const getUserInfo = (environmentId, token) => {
  return get(`${getBaseApiUrl(true)}/${environmentId}/as/userinfo`, true,
      {'Authorization': `Bearer ${token}`})
};

/**
 * Obtain an access token in a format of:
 * {access_token: "bla", token_type: "Bearer", expires_in: 3600, scope: "address phone openid profile email", id_token: "bla"}
 *
 * Note that authentication requirements to this endpoint are configured by the application’s tokenEndpointAuthMethod property
 * @param environmentId a string that specifies the environment’s UUID.
 * @param clientId a string that specifies the application’s UUID.
 * @param clientSecret a string that specifies the the application’s client secret. This property is required only if the application’s tokenEndpointAuthMethod property is set to client_secret_post.
 * @param redirectUri is a required parameter only if it was included in the original GET /{environmentId}/as/authorize request.
 * @param grant_type a string that specifies the grant type of the token request. Options are authorization_code, implicit, and client_credentials.
 * @param tokenEndpointAuthMethod a string that specifies the client authentication methods supported by the token endpoint. This is a required property. Options are none, client_secret_basic, and client_secret_post.
 * @param code a string that specifies the authorization code returned by the authorization server. This property is required only if the grant_type is set to authorization_code
 */
const getAccessToken = (environmentId, clientId, clientSecret = null,
    redirectUri, grant_type = 'authorization_code', tokenEndpointAuthMethod = 'client_secret_post', code) => {
  if(_.isEqual(tokenEndpointAuthMethod, 'client_secret_post')){
    return post(`${getBaseApiUrl(
        true)}/${environmentId}/as/token`,
        'application/x-www-form-urlencoded',
        `grant_type=${grant_type}&code=${code}&client_id=${clientId}`
        + (clientSecret ? `&client_secret=${clientSecret}` : '')
        + (redirectUri ? `&redirect_uri=${redirectUri}` : ''));
  } else {
    return get(`${getBaseApiUrl(
        true)}/${environmentId}/as/token?grant_type=${grant_type}&code=${code}&client_id=${clientId}`
        + (clientSecret ? `&client_secret=${clientSecret}` : '')
        + (redirectUri ? `&redirect_uri=${redirectUri}` : ''));
  }
};

const post = (apiPath, contentType, body = {}) =>
    new Promise((resolved, rejected) =>
        request
        .post(apiPath)
        .withCredentials()
        .send(body)
        .set('Content-Type', contentType)
        .end((err, res) => {
          if (err) {
            rejected(res ? res.body : err);
          } else {
            resolved(res.body);
          }
        }));

const get = (apiPath, getBody = false, headers = {}) =>
    new Promise((resolved, rejected) =>
        request
        .get(apiPath)
        .set(headers)
        .end((err, res) => {
          if (err) {
            rejected(res ? res.body : err);
          } else {
            resolved(getBody ? res.body : res);
          }
        }));

const getBaseApiUrl = (useAuthUrl) => {
  return useAuthUrl ?
      config.AUTH_URI : // base API URL for auth things like the flow orchestration service
      config.API_URI; // base API URL for non-auth things
};


const parseHash = () => {
  return window.location.hash.replace('#', '').split('&').reduce((prev, item) => {
    return Object.assign({[item.split('=')[0]]: decodeURIComponent(item.split('=')[1])}, prev);
  }, {});
};

const generateRandomValue = () => {
  let crypto = window.crypto || window.msCrypto;
  let D = new Uint32Array(2);
  crypto.getRandomValues(D);
  return D[0].toString(36);
};


export default {
  authorize,
  signOff,
  getAccessToken,
  getUserInfo,

  parseHash,
  generateRandomValue
}
