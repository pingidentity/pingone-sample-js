export default {
  // Application authorization details. For more information check "Getting Started" in README.md
  authDetails: {
    environmentId: "<environmentId>",
    responseType: "<responseType>",
    clientId: "<clientId>",
    clientSecret: "<clientSecret>",
    grantType: "<grantType>",
    redirectUri: "http://localhost:8080",
    logoutRedirectUri: "http://localhost:8080",
    scope: "profile address email phone",
    prompt: "login",
    tokenEndpointAuthMethod: "client_secret_post",
    maxAge: 3600,
  },

  API_URI: 'https://api.pingone.com/v1',
  AUTH_URI: 'https://auth.pingone.com'
};

