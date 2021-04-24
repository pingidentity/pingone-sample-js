const authClient = new PingOneAuthClient({
  AUTH_URI: "https://auth.pingone.com", // see Ping console - could be https://auth.pingone.eu
  environmentId: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
  clientId: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
  redirectUri: 'http://localhost:8080',
  scopes: ['openid','profile', 'email', 'address'],
  responseType: ['token', 'id_token'],
  pkce: false
});

displayViews(false);
handleCallback();

document.getElementById("signInBtn").addEventListener("click", function () {
  authClient.signIn();
}, false);

document.getElementById("signOffBtn").addEventListener("click", function () {
  authClient.signOut();
}, false);

function displayViews(isAuthenticated) {
  let signOffView = document.getElementById('signOffView');
  let signInView = document.getElementById('signInView');

  if (isAuthenticated) {
    signOffView.style.display = 'block';
    signInView.style.display = 'none';
  } else {
    signOffView.style.display = 'none';
    signInView.style.display = 'block';
  }
}

function showMessage(message, alertType) {
  document.getElementById('status').style.display = 'block';
  document.getElementById('alertMessage').innerHTML = message;
  document.getElementById('alertMessage').classList.toggle('alert-' + alertType, true);
}

 function handleCallback () {
  try {
    // Try to parse current URL and get possible tokens
    authClient.parseRedirectUrl()
        .then(tokens =>{
          if (tokens && tokens.tokens.accessToken && tokens.tokens.idToken) {
            window.history.pushState({}, document.title, "/");
            document.getElementById("tokenInfoView").innerHTML =
                `<br><b>Token Details</b><br>${jsonIntoHtmlTable(tokens.tokens.idToken.claims)}`;
            authClient.getUserInfo()
                .then(user => {
                  document.getElementById('first_name_title').innerHTML = user['given_name'];
                  document.getElementById('last_name_title').innerHTML = user['family_name'];
                  document.getElementById('userInfoView').innerHTML = '<br><b>User Details</b><br>'
                      + jsonIntoHtmlTable(user);
                });
            displayViews(true);
          }
    })
  } catch (error) {
    showMessage(error, "error");
    throw error;
  }
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

function isObject(value) {
  return value && typeof value === 'object' && value.constructor === Object;
}
