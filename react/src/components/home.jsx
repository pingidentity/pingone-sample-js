import React from 'react';
import api from '../sdk/api'
import PropTypes from 'prop-types';
import _ from "lodash";

/**
 * React component for managing the return entry point of the implicit OAuth 2.0 flow and is expecting "access_token", "id_token" or "code" in a redirect uri.
 * The user will be redirected to this point based on the redirect_uri in config.js - the URL that specifies the return entry point of this application.
 */
class Home extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      userInfo: null,
      errorMessage: ''
    };

    this.handleSignIn = this.handleSignIn.bind(this);
    this.handleSignOff = this.handleSignOff.bind(this);
    this.handleUserInfo = this.handleUserInfo.bind(this);
  }

  getAccessToken() {
    let accessToken = sessionStorage.getItem("access_token");
    if (!accessToken) {
      return api.getAccessToken(
          this.props.authDetails.environmentId,
          this.props.authDetails.clientId,
          this.props.authDetails.clientSecret,
          this.props.authDetails.redirectUri,
          this.props.authDetails.grantType,
          this.props.authDetails.tokenEndpointAuthMethod,
          sessionStorage.getItem("code"))
      .then(token => {
        sessionStorage.setItem("access_token", token.access_token);
        sessionStorage.setItem("id_token", token.id_token);
        sessionStorage.setItem("expires_in", token.expires_in);
        sessionStorage.setItem("scope", token.scope);
        return Promise.resolve(token.access_token);
      })
    } else {
      return Promise.resolve(accessToken);
    }
  }

  handleUserInfo() {
    this.getAccessToken()
    .then(accessToken => {
      return api.getUserInfo(this.props.authDetails.environmentId, accessToken)
    })
    .then(result => {
      this.setState({
        userInfo: result
      });
    })
    .catch(error => {
      const errorDetail = _.get(error, 'details[0].code', null);
      if (_.isEqual(errorDetail, 'INVALID_VALUE')) {
        if (_.get(error, 'details[0].message', null).includes(
            "Access token expired")) {
          this.setState({
            errorMessage: 'Your access token is expired. Please login again.'
          });
        } else {
          this.setState({
            errorMessage: _.get(error, 'details[0].message', null)
          });
        }
      } else if (errorDetail) {
        this.setState({
          errorMessage: errorDetail + _.get(error, 'details[0].message', null)
        });
      } else if (_.get(error, 'error', null) || _.get(error,
          'error_description', null)) {
        this.setState({
          errorMessage: _.get(error, 'error', null) + ': ' + _.get(error,
              'error_description', null)
        });
      }
      return Promise.reject(error);
    })
  }

  handleSignIn() {
    const {authDetails} = this.props;
    this.clearSession();

    let state = api.generateRandomValue();
    let nonce = api.generateRandomValue();
    sessionStorage.setItem("state", state);

    api.signIn(authDetails.environmentId,
        authDetails.responseType, authDetails.clientId,
        authDetails.redirectUri, authDetails.scope,
        state, nonce,
        authDetails.prompt, authDetails.maxAge);

  }

  handleSignOff() {
    if (sessionStorage.getItem("id_token")) {
      api.signOff(this.props.authDetails.environmentId,
          this.props.authDetails.logoutRedirectUri,
          sessionStorage.getItem("id_token"), sessionStorage.getItem("state"));
    }

    this.clearSession();
  }

  clearSession() {
    sessionStorage.removeItem("access_token");
    sessionStorage.removeItem("id_token");
    sessionStorage.removeItem("code");
    sessionStorage.removeItem("expires_in");
    sessionStorage.removeItem("scope");
    sessionStorage.removeItem("state");
  }

  componentDidMount() {
    const {authDetails} = this.props;

    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    if (!uuidRegex.test(authDetails.environmentId)) {
      this.setState({
        errorMessage: `Invalid environmentId parameter ${authDetails.environmentId} : it should be a valid UUID.  Please check it in your config.js parameters file.`,
      });
    }

    let hashes = api.parseHash();

    if (hashes && hashes.error && hashes.error_description) {
      this.setState({
        errorMessage: hashes.error + ': ' + hashes.error_description,
      });
      return;
    }

    let stateMatch = window.location.href.match('[?#&]state=([^&]*)');
    if (stateMatch && !stateMatch[1] &&
        !_.isEqual(stateMatch[1], sessionStorage.getItem("state"))) {
      this.setState({
        errorMessage: "State parameter mismatch"
      });
      return;
    }

    let codeMatch = window.location.href.match('[?#&]code=([^&]*)');

    if (hashes && hashes.access_token && hashes.id_token && hashes.expires_in) {
      sessionStorage.setItem("access_token", hashes.access_token);
      sessionStorage.setItem("id_token", hashes.id_token);
      sessionStorage.setItem("expires_in", hashes.expires_in);
      sessionStorage.setItem("scope", hashes.scope);
    } else if (codeMatch && codeMatch[1]) {
      sessionStorage.setItem("code", codeMatch[1]);
    }
    // Replace current URL without adding it to history entries
    window.history.replaceState({}, '', '/');
  }

  render() {
    const {userInfo, errorMessage} = this.state;

    let alert = errorMessage && (
        <div className="alert alert-danger">{errorMessage}</div>
    );

    // Redirect user to login page in case of access,id tokens or code absence
    if (!(sessionStorage.getItem("access_token") && sessionStorage.getItem(
        "id_token")) && !/access_token|id_token/.test(window.location.hash)
        && !sessionStorage.getItem("code") && !/code/.test(
            window.location.href)) {
      return (
          <div className="container">
            <h1>PingOne for Customers OIDC Sample</h1>
            {alert}
            <div id="signInView">
              <p>You are not currently authenticated. Click Sign On to get
                started.</p>
              <div className="input-group">
                <button type="button" className="btn"
                        onClick={this.handleSignIn}>Sign On
                </button>
              </div>
            </div>
          </div>
      );
    } else {
      const userData = userInfo && (
          <div className="input-field">
            <table className="table">
              <thead>
              <tr>
                <th>Claim</th>
                <th>Value</th>
              </tr>
              </thead>
              <tbody>
              {Object.keys(userInfo).map(key => (
                  <tr key={key}>
                    <td>{key}</td>
                    <td>{userInfo[key]}</td>
                  </tr>
              ))}
              </tbody>
            </table>
          </div>
      );
      return (
          <div className="container">
            {alert}
            <div className="home-app">
              <em>
                Congratulations! This is a secure resource.
              </em>
              <p/>
              <div className="input-group">
                <button
                    className="btn"
                    type="button"
                    onClick={this.handleSignOff}>
                  Sign Off
                </button>
              </div>

              <div className="input-field" id="user-info">
                <a href="#"
                   onClick={this.handleUserInfo}
                   id="show-user-info">
                  Show user information
                </a>
              </div>
              {userData}
            </div>
          </div>
      )
    }
  }
}

Home.propTypes = {
  authDetails: PropTypes.shape({
    environmentId: PropTypes.string.isRequired,
    clientId: PropTypes.string.isRequired,
    clientSecret: PropTypes.string,
    scope: PropTypes.string.isRequired,
    responseType: PropTypes.string,
    tokenEndpointAuthMethod: PropTypes.string.isRequired,
    grantType: PropTypes.string,
    prompt: PropTypes.string,
    redirectUri: PropTypes.string,
    logoutRedirectUri: PropTypes.string,
    maxAge: PropTypes.number
  }).isRequired
};

export default Home;
