/*
 * Copyright (C) 2015-2019 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 *
 *
 *
 * AuthOIDC js library for managing OpenID-Connect authentication.
 * It provides OIDC protocol support for JavaScript client applications and user data management operations, like data update.
 *
 * @namespace AuthOIDC
 */
var AuthOIDC = function (config) {

  /**
   * Client and Identity Provider current configuration parameters map, which keys are specifically described in {@link providerOptions} and {@link clientOptions}
   * There are some default parameter's like 'api_uri' and 'auth_uri'.
   *
   * @property {object} activeParameters
   * @property {string} activeParameters.api_uri - The primary endpoint for calling PingOne Management API services.
   * @property {string} activeParameters.auth_uri - The authorization and authentication endpoint called to request the access token required to authenticate PingOne API requests.
   *
   */
  const activeParameters = {
    api_uri: 'https://api.pingone.com/v1',
    auth_uri: 'https://auth.pingone.com'
  };

  /**
   * User Attribute Claims and their descriptions
   */
  const claimsMapping = {
    at_hash: 'Access Token hash value.',
    sub: 'Subject - Identifier for the End-User at the Issuer.',
    name: 'End-User\'s full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User\'s locale and preferences.',
    given_name: 'Given name(s) or first name(s) of the End-User.',
    family_name: 'Surname(s) or last name(s) of the End-User.',
    middle_name: 'Middle name(s) of the End-User.',
    nickname: 'Casual name of the End-User that may or may not be the same as the given_name.',
    preferred_username: 'Shorthand name by which the End-User wishes to be referred to.',
    email: 'End-User\'s preferred e-mail address.',
    updated_at: 'Time the End-User\'s information was last updated. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.',
    amr: 'Authentication Methods Reference.',
    iss: 'Issuer Identifier for the Issuer of the response.',
    nonce: 'String value used to associate a Client session with an ID Token, and to mitigate replay attacks',
    aud: 'Audience(s) that this ID Token is intended for.',
    acr: 'Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied.',
    auth_time: 'Time when the End-User authentication occurred.',
    exp: 'Expiration time on or after which the ID Token MUST NOT be accepted for processing. ',
    iat: 'Time at which the JWT was issued.',
    address_country: "Country name.",
    address_postal_code: "Zip code or postal code. ",
    address_region: "State, province, prefecture, or region. ",
    address_locality: "City or locality. ",
    address_formatted: "Full mailing address, formatted for display or use on a mailing label. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair (\"\\r\\n\") or as a single line feed character (\"\\n\").",
    address_street_address: "Full street address component, which MAY include house number, street name, Post Office Box, and multi-line extended street address information. "
        + "This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair (\"\\r\\n\") or as a single line feed character (\"\\n\").",
    amr_0: 'Authentication methods. '
  };

  /**
   * List of supported Client configuration parameters
   * @property {array} clientOptions
   * @property {string} clientOptions.client_id - A string that specifies the application’s UUID
   * @property {string} clientOptions.redirect_uri - A string that specifies the URL that specifies the return entry point of the application. This is a required property.
   * @property {string} clientOptions.post_logout_redirect_uri - A string that specifies an optional parameter that specifies the URL to which the browser is redirected after a logout has been performed.
   *                               If a post_logout_redirect_uri parameter is provided and it does not match one of the URL values of any application in the specified environment,
   *                               this condition is handled as an un-redirectable error. The URL values are strings you specified while application creation in Admin console
   * @property {string} clientOptions.api_uri - PingOne for Customers API public endpoint for calling PingOne Management API services. The default one is specified in @property activeParameters
   * @property {string} clientOptions.auth_uri - PingOne for Customers API authorization and authentication endpoint called to request the access token required to authenticate PingOne API requests. The default one is specified in @property activeParameters
   * @property {string} clientOptions.environment_id - Environment resource id this appliction is configured in
   * @readonly
   * @memberof AuthOIDC
   */
  const clientOptions = [
    'client_id',
    'redirect_uri',
    'environment_id',
    'post_logout_redirect_uri',
    'api_uri',
    'auth_uri'
  ];

  /**
   * List of the Identity Provider's configuration parameters. See {@link https://apidocs.pingidentity.com/pingone/customer/v1/api/auth/p1-a_Authorize/}
   * @property {array} providerOptions
   * @property {string} providerOptions.authorization_endpoint - Authorization Endpoint URL, i.e "https://auth.pingone.com/c2c2b4f8-c3da-4b23-abef-457ceaf25591/as/authorize"
   * @property {string} providerOptions.claim_types_supported - Supported claims types, i.e  [ "normal" ]
   * @property {string} providerOptions.claims_parameter_supported - Supported claims parameters, i.e false
   * @property {string} providerOptions.claims_supported - Supported claims, i.e [ "sub", "iss", "auth_time", "acr", "name", "given_name", "family_name", "middle_name", "preferred_username", "profile", "picture", "zoneinfo", "phone_number", "updated_at", "address", "email", "locale" ]
   * @property {string} providerOptions.end_session_endpoint - I.e: "https://auth.pingone.com/c2c2b4f8-c3da-4b23-abef-457ceaf25591/as/signoff"
   * @property {string} providerOptions.grant_types_supported - I.e:  [ "authorization_code", "implicit", "client_credentials" ]
   * @property {string} providerOptions.id_token_signing_alg_values_supported - I.e:  [ "RS256" ]
   * @property {string} providerOptions.issuer - Issuer ID "https://auth.pingone.com/c2c2b4f8-c3da-4b23-abef-457ceaf25591/as",
   * @property {string} providerOptions.jwks_uri - Identity Provider's JWKS URL, i.e "https://auth.pingone.com/c2c2b4f8-c3da-4b23-abef-457ceaf25591/as/jwks"
   * @property {string} providerOptions.request_object_signing_alg_values_supported -  I.e: [ "none" ]
   * @property {string} providerOptions.request_parameter_supported - Request parameter support, i.e false
   *
   * @readonly
   * @memberof AuthOIDC
   */
  const providerOptions = [
    "authorization_endpoint",
    "claim_types_supported",
    "claims_parameter_supported",
    "claims_supported",
    "end_session_endpoint",
    "grant_types_supported",
    "id_token_signing_alg_values_supported",
    "issuer",
    "jwks_uri",
    "request_object_signing_alg_values_supported",
    "request_parameter_supported",
    "request_uri_parameter_supported",
    "response_modes_supported",
    "response_types_supported",
    "scopes_supported",
    "subject_types_supported",
    "token_endpoint",
    "token_endpoint_auth_methods_supported",
    "userinfo_endpoint",
    "userinfo_signing_alg_values_supported"
  ];

  /**
   * Supported Login Request parameters
   * @property {array} loginRequestOptions
   * @property {string} loginRequestOptions.scope - Specifies the response type for the authorization request. The implicit grant type requires a response_type parameter value of token or id_token.
   * @property {string} loginRequestOptions.response_type - Specifies the response type for the authorization request. The implicit grant type requires a response_type parameter value of token or id_token. The default one is 'id_token'
   * @property {string} loginRequestOptions.max_age - Specifies the maximum amount of time allowed since the user last authenticated. If the max_age value is exceeded, the user must re-authenticate.
   * @property {string} loginRequestOptions.acr_values - Designates whether the authentication request includes steps for a single-factor or multi-factor authentication flow. Can be: Single_Factor or Mutli_Factor
   * @property {string} loginRequestOptions.nonce - A string that is used to associate a client session with an ID token, and to mitigate replay attacks. The value is passed through unmodified from the authentication request to the ID token.
   * @property {string} loginRequestOptions.prompt - A string that specifies whether the user is prompted to login for re-authentication.The prompt parameter can be used as a way to check for existing authentication, verifying that the user
   *                                                 is still present for the current session. For prompt=none, the user is never prompted to login to re-authenticate, which can result in an error if authentication is required. For prompt=login,
   *                                                 if time since last login is greater than the max-age, then the current session is stashed away in the flow state and treated in the flow as if there was no previous existing session. When the
   *                                                 flow completes, if the flow’s user is the same as the user from the stashed away session, the stashed away session is updated with the new flow data and persisted (preserving the existing session ID).
   *                                                 If the flow’s user is not the same as the user from the stashed away session, the stashed away session is deleted (logout) and the new session is persisted.
   * @property {string} loginRequestOptions.state - A string that specifies an optional parameter that is used to maintain state between the logout request and the callback to the endpoint specified by the post_logout_redirect_uri query parameter.
   * @readonly
   * @memberof AuthOIDC
   */
  const loginRequestOptions = [
    'scope',
    'response_type',
    'max_age',
    'acr_values',
    'nonce',
    'prompt',
    'state'
  ];

  /**
   * Initialize the authentication module with authentication information we can get from
   * url - if user just logged in and was redirected to the application, or session - if user was logged in already.
   * This is the main immediately-invoked function expression (IIFE) to use in the application
   *
   * @returns {object} - response promise from UserInfo Endpoint that returns claims about the authenticated user,
   *                     or promise object that is rejected because user is not logged in yet.
   */
  function initialize() {
    restoreInfo();
    try {
      let accessToken = sessionStorage.getItem('access_token')
          ? sessionStorage.getItem('access_token') : getAccessTokenFromUrl();
      let tokenId = sessionStorage.getItem('id_token') ? sessionStorage.getItem(
          'id_token') : getValidIdTokenFromUrl();
      let expiresIn = sessionStorage.getItem('expires_in')
          ? sessionStorage.getItem('expires_in') : getExpiresInFromUrl();
      if (accessToken && tokenId) {
        setSessionData(accessToken, tokenId, expiresIn);
        return getUserInfo(accessToken);
      }
    } catch (e) {
      // Expected behaviour when there are no tokens in URL we are expecting
      // (user is not logged in yet), or other validations didn't pass
      if (e.name !== 'AuthException') {
        throw e;
      }
    } finally {
      // Clear URL hash
      window.location.hash = '';
    }
    return Promise.resolve('User is not logged in yet');
  }

  /**
   * Initialize PingIdentity OpenID Connect client
   * @param clientInfo
   */
  function setConfig(clientInfo) {
    setClientInfo(clientInfo);
    let providerInfo = discover();
    setProviderInfo(providerInfo);
    storeInfo(providerInfo, clientInfo);
  }

  /**
   * Sets the Identity Provider's configuration parameters (using discovery information)
   * @function setProviderInfo
   * @memberof AuthOIDC
   * @param {object} providerParams      - The Identity Provider's configuration options described in {@link providerOptions}
   */
  function setProviderInfo(providerParams) {
    let params = providerOptions;
    try {
      if (typeof providerParams !== 'undefined') {
        for (let i = 0; i < params.length; i++) {
          if (typeof providerParams[params[i]] !== 'undefined') {
            activeParameters[params[i]] = providerParams[params[i]];
          }
        }
      }
      return true;
    } catch (e) {
      throw new AuthException(
          "Unable to set the Identity Provider's configuration parameters: "
          + e.toString());
    }
  }

  /**
   * Sets the Client's configuration parameters
   * @function setClientInfo
   * @memberof AuthOIDC
   * @param {object} clientParams      - The Client's configuration options described in {@link clientOptions}
   * @returns {boolean}       Indicates status of call
   */
  function setClientInfo(clientParams) {
    let params = clientOptions;
    try {
      for (let i = 0; i < params.length; i++) {
        if (typeof clientParams[params[i]] !== 'undefined') {
          activeParameters[params[i]] = clientParams[params[i]];
        }
      }
    } catch (e) {
      throw new AuthException(
          "Unable to set the Client's configuration parameters: "
          + e.toString());
    }
  }

  /**
   * Set configuration options in the browser session storage
   *
   * @param accessToken
   * @param idToken
   * @param expiresIn the time that the access token will expire at
   */
  function setSessionData(accessToken, idToken, expiresIn) {
    sessionStorage.setItem('access_token', accessToken);
    sessionStorage.setItem('id_token', idToken);
    if (expiresIn) {
      sessionStorage.setItem('expires_in', JSON.stringify(
          expiresIn * 1000 + new Date().getTime()
      ));
    }
  }

  /**
   * Clear browser session storage from previous session
   */
  function clearSessionData() {
    sessionStorage.removeItem('state');
    sessionStorage.removeItem('nonce');
    sessionStorage.removeItem('access_token');
    sessionStorage.removeItem('id_token');
    sessionStorage.removeItem('expires_in');
  }

  /**
   * Store/clear the Identity Provider and Client configuration options in the browser session storage to reuse them later
   * @function storeInfo
   * @memberof AuthOIDC
   * @param {object} providerInfo    - The Identity Provider's configuration options described in {@link providerOptions}
   * @param {object} clientInfo      - The Client's configuration options described in {@link clientOptions}
   */
  function storeInfo(providerInfo, clientInfo) {
    let pOptions = providerOptions;
    let cOptions = clientOptions;
    let pInfo = {};
    let cInfo = {};

    try {
      if (providerInfo) {
        for (let i = 0; i < pOptions.length; i++) {
          if (typeof providerInfo[pOptions[i]] != 'undefined') {
            pInfo[pOptions[i]] = providerInfo[pOptions[i]];
          }
        }
        sessionStorage.setItem('providerInfo', JSON.stringify(pInfo));
      } else {
        if (sessionStorage.getItem('providerInfo')) {
          sessionStorage.removeItem('providerInfo');
        }
      }

      if (clientInfo) {
        for (let i = 0; i < cOptions.length; i++) {
          if (typeof clientInfo[cOptions[i]] != 'undefined') {
            cInfo[cOptions[i]] = clientInfo[cOptions[i]];
          }
        }
        sessionStorage.setItem('clientInfo', JSON.stringify(cInfo));
      } else {
        if (sessionStorage.getItem('clientInfo')) {
          sessionStorage.removeItem('clientInfo');
        }
      }
    } catch (e) {
      throw new AuthException(
          'Unable to store the Identity Provider and Client configuration options: '
          + e.toString());
    }
  }

  /**
   * Load and restore the Identity Provider and Client configuration options from the browser session storage
   * @function restoreInfo
   * @memberof AuthOIDC
   */
  function restoreInfo() {
    let providerInfo = sessionStorage.getItem('providerInfo');
    let clientInfo = sessionStorage.getItem('clientInfo');
    try {
      if (providerInfo) {
        setProviderInfo(JSON.parse(providerInfo));
      }
      if (clientInfo) {
        setClientInfo(JSON.parse(clientInfo));
      }
    } catch (e) {
      throw new AuthException(
          'Unable to restore the Identity Provider and Client configuration options: '
          + e.toString());
    }
  }

  /**
   * Check whether the required configuration parameters are set
   * @function checkRequiredInfo
   * @param {array} params    - List of Identity Provider and client configuration parameters
   * @memberof AuthOIDC
   * @return {boolean}        - Indicates whether the options have been set
   *
   */
  function checkRequiredInfo(params) {
    try {
      if (params) {
        for (let i = 0; i < params.length; i++) {
          if (!activeParameters[params[i]]) {
            throw new AuthException(
                'Required parameter not set - ' + params[i]);
          }
        }
      }
      return true;
    } catch (e) {
      throw new AuthException(
          'Unable to check whether the required configuration parameters are set: '
          + e.toString());
    }

  }

  /**
   * Redirect to the Identity Provider for authentication (default values are: scope=openid, response_type=id_token)
   * @param {object} reqOptions    - Optional authentication request options. See {@link loginRequestOptions}
   * @throws {AuthException}
   */
  function signIn(reqOptions) {
    try {
      clearSessionData();

      // verify required parameters
      checkRequiredInfo(
          ['client_id', 'redirect_uri', 'authorization_endpoint']);

      let reqOptionsExist = !!reqOptions;
      let state = null;
      let nonce = null;

      if (reqOptionsExist && (reqOptions['nonce'] && reqOptions['state'])) {
        state = reqOptions['state'];
        nonce = reqOptions['nonce']
      }

      // Replace state and nonce with secure ones
      let crypto = window.crypto || window.msCrypto;
      if (crypto && crypto.getRandomValues) {
        let D = new Uint32Array(2);
        crypto.getRandomValues(D);
        state = reqOptionsExist && reqOptions['state'] ? reqOptions['state']
            : D[0].toString(36);
        nonce = reqOptionsExist && reqOptions['nonce'] ? reqOptions['nonce']
            : D[1].toString(36);
      } else {
        let byteArrayToLong = function (/*byte[]*/byteArray) {
          let value = 0;
          for (let i = byteArray.length - 1; i >= 0; i--) {
            value = (value * 256) + byteArray[i];
          }
          return value;
        };

        let sRandom = new SecureRandom();
        let randState = new Array(4);
        sRandom.nextBytes(randState);
        state = byteArrayToLong(randState).toString(36);

        let randNonce = new Array(4);
        sRandom.nextBytes(randNonce);
        nonce = byteArrayToLong(randNonce).toString(36);
      }

      // Store the them in session storage
      sessionStorage.setItem('state', state);
      sessionStorage.setItem('nonce', nonce);

      let response_type = 'id_token';
      let scope = 'openid';
      let acr_values = null;
      let max_age = null;

      if (reqOptionsExist) {
        if (reqOptions['response_type']) {
          let parts = reqOptions['response_type'].split(' ');
          let temp = [];
          if (parts) {
            for (let i = 0; i < parts.length; i++) {
              if (parts[i] === 'code' || parts[i] === 'token' || parts[i]
                  === 'id_token') {
                temp.push(parts[i]);
              }
            }
          }
          if (temp) {
            response_type = temp.join(' ');
          }
        }

        if (reqOptions['scope']) {
          scope = reqOptions['scope'];
        }
        if (reqOptions['acr_values']) {
          acr_values = reqOptions['acr_values'];
        }
        if (reqOptions['max_age']) {
          max_age = reqOptions['max_age'];
        }
      }

      // Construct the redirect URL for getting an id token, response_type of "token id_token" (note the space), scope of "openid", and some value for nonce is required.
      // client_id must be the consumer key of the connected app. redirect_uri must match the callback URL configured for the connected app.

      let optParams = '';
      if (acr_values) {
        optParams += '&acr_values=' + acr_values;
      }
      if (max_age) {
        optParams += '&max_age=' + max_age;
      }

      let url = activeParameters['authorization_endpoint']
          + '?response_type=' + response_type
          + '&client_id=' + activeParameters['client_id']
          + '&redirect_uri=' + activeParameters['redirect_uri']
          + '&state=' + state
          + '&scope=' + scope
          + '&nonce=' + nonce
          + optParams;

      if (reqOptions['window']) {
        return window.open(url, '_blank', reqOptions['window']);
      }
      window.location.replace(url);
    } catch (e) {
      throw new AuthException(
          'Unable to redirect to the Identity Provider for authenticaton: '
          + e.toString());
    }
  }

  /**
   * Call the end session endpoint to initiate the logout flow notifying the identity provider that the End-User has logged out of the site and might want to log out of the identity provider as well.
   * In this case, after having logged the End-User out of the application, it (application) redirects the End-User's User Agent to the identity provider's logout endpoint URL
   * @function signOff
   * @memberof AuthOIDC
   */
  function signOff() {
    let logOffURL = JSON.parse(
        sessionStorage.getItem('providerInfo'))['end_session_endpoint']
        + '?id_token_hint='
        + sessionStorage.getItem('id_token');

    //state	string specifies an optional parameter that is used to maintain state between the logout request and the callback to the endpoint specified by the post_logout_redirect_uri query parameter.
    if (activeParameters['post_logout_redirect_uri']) {
      logOffURL = logOffURL + '&post_logout_redirect_uri='
          + activeParameters['post_logout_redirect_uri'] + '&state='
          + sessionStorage.getItem('state');
    }
    clearSessionData();
    storeInfo(null, null);
    window.location.href = logOffURL;
  }

  /**
   * Update user attribute values specified in the request body. Attributes omitted from the request body are not updated or removed
   * @function updateUser
   * @memberof AuthOIDC
   * @param {string} firstName     - user's first name
   * @param {string} lastName      - user's last name
   * @returns {Promise} - promise of update endpoint response
   * @throws {AuthException}
   *
   */
  function updateUser(firstName, lastName) {
    checkRequiredInfo(['environment_id', 'api_uri']);

    let userId = getTokenJson()['sub'];
    return fetch(activeParameters['api_uri'] + '/environments/'
        + activeParameters['environment_id'] + '/users/'
        + userId, {
      method: "PATCH",
      headers: new Headers({
        'Authorization': 'Bearer ' + sessionStorage.getItem('access_token'),
        'Content-Type': 'application/json'
      }),
      body: JSON.stringify({
        "name": {
          "given": firstName,
          "family": lastName
        }
      })
    })
    .then(handleResponse);
  }

  /**
   * Request and return the user information from the Identity Provider.
   * @function getUserInfo
   * @memberof AuthOIDC
   * @param {string} access_token     - Access Token string
   * @returns {object|null}  - The promise of JSON object with the user claims
   * @throws {AuthException}
   */
  function getUserInfo(access_token) {
    let providerInfo = discover();

    return fetch(providerInfo['userinfo_endpoint'], {
      method: "POST",
      headers: new Headers({
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/x-www-form-urlencoded'
      })
    })
    .then(handleResponse);
  }

  /**
   * Verifies the ID Token signature using reaching jwks_uri of the
   * Identity Provider Configuration options set via {@link setProviderInfo}.
   * Supports only RSA signatures
   * @param {string }id_token      - The ID Token string
   * @returns {boolean}            - Indicates whether the signature is valid or not
   * @see setProviderInfo
   * @throws {AuthException}
   */
  function verifyIdTokenSig(id_token) {
    try {
      let verified = false;
      let requiredParam = activeParameters['jwks_uri'];
      if (!requiredParam) {
        throw new AuthException('jwks_uri parameter was not set');
      } else if (id_token) {
        let idtParts = getIdTokenParts(id_token);
        let header = getJsonObject(idtParts[0]);
        let jwks = fetchJson(activeParameters['jwks_uri']);
        if (!jwks) {
          throw new AuthException('No JWK keyset');
        } else {
          if (header['alg'] && header['alg'].substr(0, 2) === 'RS') {
            let jwk = jwkGetKey(jwks, 'RSA', 'sig', header['kid']);
            if (!jwk) {
              new AuthException('No matching JWK found');
            } else {
              verified = rsaVerifyJWS(id_token, jwk[0]);
            }
          } else {
            throw new AuthException(
                'Unsupported JWS signature algorithm ' + header['alg']);
          }
        }
      }
      return verified;
    } catch (e) {
      throw new AuthException(
          'Unable to verify the ID Token signature: ' + e.toString());
    }
  }

  /**
   * Check whether the current time is past the access token's expiry time plus access and id tokens presence
   * @returns {boolean}         - true if every check succeeds
   */
  function isAuthenticated() {
    let notExpired = sessionStorage.getItem('expires_in') &&
        new Date().getTime() < JSON.parse(sessionStorage.getItem('expires_in'));
    return sessionStorage.getItem('access_token')
        && sessionStorage.getItem('id_token')
        && notExpired;
  }

  /**
   * Validates the information in the ID Token against configuration data in the Identity Provider
   * and Client configuration set via {@link setProviderInfo} and set via {@link setClientInfo}
   * @param {string} id_token      - The ID Token string
   * @returns {boolean}            - Validity of the ID Token
   * @throws {AuthException}
   */
  function isValidIdToken(id_token) {
    try {
      let valid = false;
      checkRequiredInfo(['issuer', 'client_id']);

      if (id_token) {
        let idtParts = getIdTokenParts(id_token);
        let payload = getJsonObject(idtParts[1]);
        if (payload) {
          let now = new Date() / 1000;
          if (payload['iat'] > now + (5 * 60)) {
            throw new AuthException(
                'ID Token issued time is later than current time');
          }
          if (payload['exp'] < now - (5 * 60)) {
            throw new AuthException('ID Token expired');
          }
          let audience = null;
          if (payload['aud']) {
            if (payload['aud'] instanceof Array) {
              audience = payload['aud'][0];
            } else {
              audience = payload['aud'];
            }
          }
          if (audience !== activeParameters['client_id']) {
            throw new AuthException('invalid audience');
          }
          if (payload['iss'] !== activeParameters['issuer']) {
            throw new AuthException('invalid issuer ' + payload['iss'] + ' != '
                + activeParameters['issuer']);
          }
          if (payload['nonce'] !== sessionStorage.getItem('nonce')) {
            throw new AuthException('invalid nonce');
          }
          valid = true;
        } else {
          throw new AuthException('Unable to parse JWS payload');
        }
      }
      return valid;
    } catch (e) {
      throw new AuthException(
          'Unable to validate information in the ID Token: ' + e.toString());
    }
  }

  /**
   * Verifies the JWS string using the JWK
   * @param {string} jws      - The JWS string
   * @param {object} jwk      - The JWK Key that will be used to verify the signature
   * @returns {boolean}       - Validity of the JWS signature
   * @throws {AuthException}
   */
  function rsaVerifyJWS(jws, jwk) {
    try {
      if (jws && typeof jwk === 'object') {
        if (jwk['kty'] === 'RSA') {
          let verifier = KJUR.jws.JWS;
          if (jwk['n'] && jwk['e']) {
            let pubkey = KEYUTIL.getKey({kty: 'RSA', n: jwk['n'], e: jwk['e']});
            return verifier.verify(jws, pubkey, ['RS256']);
          } else if (jwk['x5c']) {
            return verifier.verifyJWSByPemX509Cert(jws,
                "-----BEGIN CERTIFICATE-----\n" + jwk['x5c'][0]
                + "\n-----END CERTIFICATE-----\n");
          }
        } else {
          throw new AuthException('No RSA kty in JWK');
        }
      }
    } catch (e) {
      throw new AuthException(
          'Unable to verify the JWS string: ' + e.toString());
    }
  }

  /**
   * Get the ID Token from the current page URL whose signature is verified and contents validated
   * against the configuration data set via {@link setProviderInfo} and {@link setClientInfo}
   * @returns {string|null}
   * @throws {AuthException}
   */
  function getValidIdTokenFromUrl() {
    try {
      let url = window.location.href;

      // Check if there was an error parameter
      let error = url.match('[?&]error=([^&]*)');
      if (error) {
        // If so, extract the error description and display it
        let description = url.match('[?&]message(*)');
        throw new AuthException(error[1] + ' Description: ' + description[1]);
      }

      // Extract state from the state parameter
      let urlState = getState();
      let storedState = sessionStorage.getItem('state');
      let goodState = urlState === storedState;

      // Extract id token from the id_token parameter
      let match = url.match('[?#&]id_token=([^&]*)');
      if (!goodState) {
        throw new AuthException('State mismatch');
      } else if (match) {
        let id_token = match[1]; // String captured by ([^&]*)

        if (id_token) {
          let sigVerified = verifyIdTokenSig(id_token);
          let valid = isValidIdToken(id_token);
          if (sigVerified && valid) {
            return id_token;
          }
        } else {
          throw new AuthException('Could not retrieve ID Token from the URL');
        }
      } else {
        throw new AuthException('No ID Token returned');
      }
    } catch (e) {
      throw new AuthException(
          'Unable to get the ID Token from the current page URL: '
          + e.toString());
    }
  }

  /**
   * Get State from the current page URL
   * @returns {string|null} State
   */
  function getState() {
    try {
      let url = window.location.href;
      let smatch = url.match('[?#&]state=([^&]*)');
      if (smatch && smatch[1]) {
        return decodeURIComponent(smatch[1]);
      }
    } catch (e) {
      throw new AuthException(
          'Unable to get the State from the current page URL: ' + e.toString());
    }
  }

  /**
   * Get Access Token from the current page URL
   * @returns {string|null}  Access Token
   */
  function getAccessTokenFromUrl() {
    try {
      let url = window.location.href;
      let token = url.match('[?#&]access_token=([^&]*)');
      if (token) {
        return token[1];
      }
    } catch (e) {
      throw new AuthException(
          'Unable to get the Access Token from the current page URL: '
          + e.toString());
    }
  }

  /**
   * Get Authorization Code from the current page URL
   * @returns {string|null}  Authorization Code
   */
  function getCodeFromUrl() {
    try {
      let url = window.location.href;
      let code = url.match('[?&]code=([^(&)]*)');
      if (code) {
        return code[1];
      }
    } catch (e) {
      throw new AuthException(
          'Unable to get the Authorization Code from the current page URL: '
          + e.toString());
    }
  }

  /**
   * Get Authorization Code from the current page URL
   * @returns {number}  Authorization Code
   */
  function getExpiresInFromUrl() {
    try {
      let url = window.location.href;
      let expiresIn = url.match('[?#&]expires_in=([^(&)]*)');
      if (expiresIn) {
        return parseInt(expiresIn[1], 10);
      } else {
        return null;
      }
    } catch (e) {
      throw new AuthException(
          'Unable to get \'expires_in\' from the current page URL: '
          + e.toString());
    }
  }

  /**
   * Splits the ID Token string into the individual JWS parts
   * @param  {string} id_token    - ID Token
   * @returns {Array} An array of the JWS compact serialization components (header, payload, signature)
   */
  function getIdTokenParts(id_token) {
    try {
      let jws = new KJUR.jws.JWS();
      jws.parseJWS(id_token);
      return [jws.parsedJWS.headS, jws.parsedJWS.payloadS,
        jws.parsedJWS.si];
    } catch (e) {
      throw new AuthException(
          'Unable to split the ID Token string: ' + e.toString());
    }
  }

  /**
   * Get the contents of the ID Token payload as an JSON object
   * @param {string} id_token     - ID Token
   * @returns {object}            - The ID Token payload JSON object
   */
  function getIdTokenPayload(id_token) {
    try {
      let parts = getIdTokenParts(id_token);
      if (parts) {
        return getJsonObject(parts[1]);
      }
    } catch (e) {
      throw new AuthException(
          'Unable to get the contents of the ID Token payload: '
          + e.toString());
    }
  }

  /**
   * Get the JSON object from the JSON string
   * @param {string} jsonString    - JSON string
   * @returns {object|null}   JSON object
   */
  function getJsonObject(jsonString) {
    try {
      let jws = KJUR.jws.JWS;
      if (jws.isSafeJSONString(jsonString)) {
        return jws.readSafeJSONString(jsonString);
      }
    } catch (e) {
      throw new AuthException(
          'Unable to get the JSON object from JSON string: ' + e.toString());
    }
  }

  /**
   * Retrieves the JSON file at the specified URL. The URL must have CORS enabled for this function to work.
   * @param {string} url      - URL to fetch the JSON file
   * @returns {string|null}    contents of the URL or null
   * @throws {AuthException}
   */
  function fetchJson(url) {
    try {
      let request = new XMLHttpRequest();
      request.open('GET', url, false);
      request.send(null);

      if (request.status === 200) {
        return request.responseText;
      } else {
        throw new AuthException(
            "fetchJson - " + request.status + ' ' + request.statusText);
      }
    } catch (e) {
      throw new AuthException(
          'Unable to retrieve JSON file at ' + url + ' : ' + e.toString());
    }
  }

  /**
   * Retrieve the JWK key that matches the input criteria
   * @param {string|object} jwkIn     - JWK Keyset string or object
   * @param {string} kty              - The 'kty' to match (RSA|EC). Only RSA is supported.
   * @param {string}use               - The 'use' to match (sig|enc).
   * @param {string}kid               - The 'kid' to match
   * @returns {array}                 Array of JWK keys that match the specified criteria
   */
  function jwkGetKey(jwkIn, kty, use, kid) {
    try {
      let jwk = null;
      let foundKeys = [];

      if (jwkIn) {
        if (typeof jwkIn === 'string') {
          jwk = getJsonObject(jwkIn);
        } else if (typeof jwkIn === 'object') {
          jwk = jwkIn;
        }

        if (jwk != null) {
          if (typeof jwk['keys'] === 'object') {
            if (jwk.keys.length === 0) {
              return null;
            }

            for (let i = 0; i < jwk.keys.length; i++) {
              if (jwk['keys'][i]['kty'] === kty) {
                foundKeys.push(jwk.keys[i]);
              }
            }

            if (foundKeys.length === 0) {
              return null;
            }

            if (use) {
              let temp = [];
              for (let j = 0; j < foundKeys.length; j++) {
                if (!foundKeys[j]['use']) {
                  temp.push(foundKeys[j]);
                } else if (foundKeys[j]['use'] === use) {
                  temp.push(foundKeys[j]);
                }
              }
              foundKeys = temp;
            }
            if (foundKeys.length === 0) {
              return null;
            }

            if (kid) {
              temp = [];
              for (let k = 0; k < foundKeys.length; k++) {
                if (foundKeys[k]['kid'] === kid) {
                  temp.push(foundKeys[k]);
                }
              }
              foundKeys = temp;
            }
            if (foundKeys.length === 0) {
              return null;
            } else {
              return foundKeys;
            }
          }
        }
      }
    } catch (e) {
      throw new AuthException(
          'Unable to retrieve the JWK key: ' + e.toString());
    }
  }

  /**
   * Performs Identity Provider discovery
   * @function discover
   * @memberof AuthOIDC
   * @returns {object|null}     - The JSON object of the discovery document
   * @throws {AuthException}
   */
  function discover() {
    checkRequiredInfo(['auth_uri', 'environment_id']);
    try {
      let discoveryDoc = fetchJson(activeParameters['auth_uri'] + '/'
          + activeParameters['environment_id']
          + '/as/.well-known/openid-configuration');
      if (discoveryDoc) {
        return getJsonObject(discoveryDoc);
      }
    } catch (e) {
      throw new AuthException(
          'Unable to perform Identity Provider discovery: ' + e.toString());
    }
  }

  function getTokenJson() {
    let id_token = sessionStorage.getItem('id_token');
    return JSON.parse(getIdTokenParts(id_token)[1]);
  }

  function showTokenClaimsInfo() {
    return jsonIntoHtmlTable(getTokenJson());
  }

  function showUserInfo() {
    return getUserInfo(sessionStorage.getItem('access_token'))
    .then(data => jsonIntoHtmlTable(data));
  }

  /**
   * Transform json content into html table element
   * @param json
   * @returns {string}
   */
  function jsonIntoHtmlTable(json) {
    try {
      return '\n<table class="table"><tr>'
          + '<th>Claim</th><th>Description</th><th>Value</th></tr>'
          + addTableBody(json) + '\n</table>';
    } catch (e) {
      throw new AuthException(
          'Unable to format json into HTML table:' + e.toString());
    }
  }

  /**
   * Create table body from json object
   * @param jsonObject json object to create a table from
   * @returns {string|string}
   */
  function addTableBody(jsonObject) {
    let htmlTableBody = '';
    for (let claim in jsonObject) {
      // In case that is a nested element like address modify its keys by adding '_' between parent and child keys(i.s parentKey_childKey)
      // for getting a proper claim description from the map
      if (isObject(jsonObject[claim])) {
        let renamedKeys = Object.keys(jsonObject[claim]).reduce((acc, key) => ({
          ...acc,
          ...{[claim + '_' + key]: jsonObject[claim][key]}
        }), {});
        htmlTableBody = htmlTableBody + addTableBody(renamedKeys)
      } else {
        htmlTableBody = htmlTableBody + '\n<tr><td>' + claim + '</td><td>'
            + (claimsMapping[claim]
                ? claimsMapping[claim] : '') + '</td><td>' + jsonObject[claim]
            + '</td></tr>';
      }
    }
    return htmlTableBody;
  }

  /**
   * Transform json content into html description list element
   * @param json
   * @returns {string}
   */
  function jsonIntoHtmlDescriptions(json) {
    try {
      let htmlString = '\n<dl>';
      for (let claim in json) {
        htmlString = htmlString + '\n<dt>' + claim + '</dt><dd>'
            + json[claim] + '</dd>';
      }
      return htmlString + '\n</dl>';
    } catch (e) {
      throw new AuthException(
          'Unable to format json into HTML table:' + e.toString());
    }
  }

  function isObject(value) {
    return value && typeof value === 'object' && value.constructor === Object;
  }

  /**
   * Handle all fetch response's
   *
   * @param response
   * @returns {Promise<T | never>}
   */
  function handleResponse(response) {
    let contentType = response.headers.get('content-type');
    if (contentType.includes('application/json')) {
      return handleJSONResponse(response)
    } else if (contentType.includes('text/html')) {
      return handleTextResponse(response)
    } else {
      // Other response types as necessary. I haven't found a need for them yet though.
      throw new Error(`Sorry, content-type ${contentType} not supported`)
    }
  }

  /**
   * Handle json fetch response's
   * @param response json type response
   * @returns {Promise<T | never>}
   */
  function handleJSONResponse(response) {
    return response.json()
    .then(json => {
      if (response.ok) {
        return json
      } else {
        return Promise.reject(Object.assign({}, json, {
          status: response.status,
          statusText: response.statusText
        }))
      }
    })
  }

  /**
   * Handle text fetch response's
   * @param response text type response
   * @returns {Promise<T | never>}
   */
  function handleTextResponse(response) {
    return response.text()
    .then(text => {
      if (response.ok) {
        return text
      } else {
        return Promise.reject({
          status: response.status,
          statusText: response.statusText,
          err: text
        })
      }
    })
  }

  if (config) {
    setConfig(config)
  }

  // ************************************************
  // *****************  Exposed API  *****************
  // ************************************************
  return {
    setConfig: setConfig,
    isAuthenticated: isAuthenticated,
    init: initialize,
    showUserInfo: showUserInfo,
    showTokenClaimsInfo: showTokenClaimsInfo,

    signIn: signIn,
    signOff: signOff,
    updateUser: updateUser,

    formatIntoDescription: jsonIntoHtmlDescriptions,
    formatIntoTable: jsonIntoHtmlTable
  }
};

/**
 * AuthException
 * @param {string } message  - The exception error message
 * @constructor
 */
function AuthException(message) {
  this.name = 'AuthException';
  this.message = message;
}

AuthException.prototype = new Error();
AuthException.prototype.constructor = AuthException;
