export default {
  // Application authorization details. For more information check "Getting Started" in README.md
  authDetails: {
    environmentId: "c2c2b4f8-c3da-4b23-abef-457ceaf25591",
    // responseType: "<responseType>",
    clientId: "1eb1030b-36fc-4584-a0c5-6366a539f73a",
    //clientSecret: "c7G_gvTwZ.MOlF7YWqCLivRX0isTaQUAMHW15mKFAxkCZif4s.wr_8gERdfKmmGV",
    grantType: "implicit",
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

