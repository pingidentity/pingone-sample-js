import json
import logging
from urllib.parse import urljoin, quote_plus
from functools import wraps, partial
import jwt
import requests
from oauthlib.common import generate_nonce

from requests_oauthlib import OAuth2Session
from flask import abort, redirect, request, session
from oauthlib.oauth2 import WebApplicationClient, BackendApplicationClient, \
    MobileApplicationClient

from services.configuration import Configuration

# OpenID Connect/OAuth 2 protocol related parameters
TOKEN_TYPE = 'token_type'
SCOPE = 'scope'
EXPIRES_IN = 'expires_in'
CODE = 'code'
STATE = 'state'
NONCE = 'nonce'
ID_TOKEN = 'id_token'

#  Authorization grant types by which a client application obtains an authorization grant in the form of an access token.
CLIENT_CREDENTIALS_GRANT_TYPE = 'client_credentials'
IMPLICIT_GRANT_TYPE = 'implicit'

# Configuration parameters from config.cfg
RESPONSE_TYPE_CONFIG = 'RESPONSE_TYPE'
SECRET_KEY_CONFIG = 'SECRET_KEY'
SCOPE_CONFIG = 'SCOPE'

# Application internal parameters
AUTH_STATE_KEY = 'oauth_state'
AUTH_NONCE_KEY = 'oauth_nonce'
AUTH_TOKEN_KEY = 'oauth_token'
USER_DETAILS = 'user_details'
RESPONSE_URL = 'responseUrl'


class AuthClient(Configuration):

    def __init__(self, app):
        Configuration.__init__(self, app.config)

        self.config = app.config
        self.issuer = '{}{}/as'.format(self.authentication_uri, self.environment_id)
        self.oauth_url = '{}/authorize'.format(self.issuer)
        self.oauth_token_url = '{}/token'.format(self.issuer)
        self.signOff_url = '{}/signoff'.format(self.issuer)
        self.user_info_url = '{}/userinfo'.format(self.issuer)
        self.jwks_url = '{}/jwks'.format(self.issuer)

    def oauth_redirect(self, oauth_session):
        """
        redirect to the oauth url with setting the anti-forgery 'state' token in the session
        :param oauth_session: instance of OAuth 2 extension to :class:`requests_oauthlib.OAuth2Session`.
        """
        nonce = generate_nonce()
        authorization_url, state = oauth_session.authorization_url(url=self.oauth_url, prompt=self.prompt,
                                                                   max_age=self.max_age, nonce=nonce)
        session[AUTH_STATE_KEY] = state
        session[AUTH_NONCE_KEY] = nonce
        session.modified = True
        return redirect(authorization_url)

    def get_oauth_token(self, verify_state=True):

        """
        return an oauth token for the user - expects the request it gets back from the
        oauth provider to have a "code" parameter and a `state` parameter
        if the state from the params (`stated_state`) doesn't match the `oauth_state`
        (`known_state`) stored in the session, we'll 403 af outta here
        abort with a 403 if anything goes wrong when fetching the token from the oauth
        provider
        :param verify_state:
        :return:
        """
        oauth_session = self.get_oauth_session()

        if self.grant_type and self.grant_type == IMPLICIT_GRANT_TYPE:
            return self.get_token_from_implicit_flow(oauth_session)

        code = request.args.get(CODE)
        stated_state = request.args.get(STATE)
        known_state = session.get(AUTH_STATE_KEY)

        if verify_state and (not known_state or not stated_state or stated_state != known_state):
            # the requests_oauthlib library won't handle this check for us unless
            # we provide the known_state to the OAuth2Session constructor *and* use the
            # authorization_response kwarg (which is a url string) with `fetch_token`
            # we're not doing that since authorization_response must have https scheme
            # or requests_oauthlib barfs out
            abort(403)

        return oauth_session.fetch_token(self.oauth_token_url, client_secret=self.client_secret, code=code,
                                         include_client_id=self.include_client_id)

    def get_oauth_session(self):
        known_state = session.get(AUTH_STATE_KEY)
        redirect_url = urljoin(request.url_root, self.redirect_path)

        if self.grant_type and self.grant_type == CLIENT_CREDENTIALS_GRANT_TYPE:
            client = BackendApplicationClient(client_id=self.client_id)
            oauth_session = OAuth2Session(client=client, token=session.get(AUTH_TOKEN_KEY))

        elif self.grant_type and self.grant_type == IMPLICIT_GRANT_TYPE:
            client = MobileApplicationClient(self.client_id)
            client.response_type = self.config.get(RESPONSE_TYPE_CONFIG)
            oauth_session = OAuth2Session(client_id=self.client_id,
                                          state=known_state,
                                          scope=self.config.get(SCOPE_CONFIG).split(),
                                          redirect_uri=redirect_url,
                                          client=client,
                                          token=session.get(AUTH_TOKEN_KEY))
        else:
            client = WebApplicationClient(self.client_id)
            oauth_session = OAuth2Session(client_id=self.client_id,
                                          state=known_state,
                                          scope=self.config.get(SCOPE_CONFIG).split(),
                                          redirect_uri=redirect_url,
                                          client=client,
                                          token=session.get(AUTH_TOKEN_KEY))

        return oauth_session

    def get_id_token(self):
        # Reading the user id token claimset without performing validation of the signature or any of the registered claim
        # names for getting a "sub" claim (the user ID)
        return jwt.decode(session.get(AUTH_TOKEN_KEY).get('access_token'), self.config.get(SECRET_KEY_CONFIG),
                          verify=False)

    def get_logout_url(self):
        """
        :return:  the endpoint to initiate end user logout if user is authenticated and has a valid  ID token that indicates the identity of the user
        """
        if self.is_authenticated() and session.get(AUTH_TOKEN_KEY) and session.get(AUTH_TOKEN_KEY).get(ID_TOKEN):
            logout_url = '{}?id_token_hint={}'.format(self.signOff_url, session.get(
                AUTH_TOKEN_KEY).get(ID_TOKEN))
            if self.logout_uri:
                logout_url = logout_url.join('&post_logout_redirect_uri={}'.format(self.logout_uri))
            return logout_url
        return None

    def get_user_details(self):
        if self.is_authenticated():
            if not session.get(USER_DETAILS):
                oauth_session = self.get_oauth_session()
                user_details = oauth_session.get(self.user_info_url)
                user_details.raise_for_status()
                session[USER_DETAILS] = user_details.json()
            return session[USER_DETAILS]
        return None

    def callback(self, view_func=None, **options):
        # If called without method, we've been called with optional arguments.
        # We return a decorator with the optional arguments filled in.
        # Next time round we'll be decorating method.
        if view_func is None:
            return partial(self.callback, **options)

        @wraps(view_func)
        def view_wrapper(*args, **kwargs):
            if not self.is_authenticated():
                token = self.get_oauth_token()
                if token is not None:
                    self.validate_token(token[ID_TOKEN])
                    session[AUTH_TOKEN_KEY] = token

                    # force our changes to be recognized
                    session.modified = True
            else:
                logging.info('Application was already logged in')
            return view_func(*args, **kwargs)

        return view_wrapper

    def token_required(self, view_func=None):
        if view_func is None:
            return partial(self.token_required)

        @wraps(view_func)
        def view_wrapper(*args, **kwargs):
            if not self.is_authenticated():
                abort(403,
                      description='This resource is protected and requires user authentication. Please login firstly. ')
            else:
                logging.info('Application has a token already.')
            return view_func(*args, **kwargs)

        return view_wrapper

    def login_required(self, view_func=None):
        if view_func is None:
            return partial(self.login_required)

        @wraps(view_func)
        def view_wrapper(*args, **kwargs):
            if self.is_authenticated():
                return view_func(*args, **kwargs)
            oauth_session = self.get_oauth_session()
            return self.oauth_redirect(oauth_session)

        return view_wrapper

    def validate_token(self, token, verify_nonce=True):
        """
        Validate JWT token
        :param token: JWT token
        :param verify_nonce:
        :return:
        """

        id_token_parts = token.split('.')
        if len(id_token_parts) < 3:
            abort(403, 'Invalid token: unable to split the token content. ')

        keys = {k['kid']: jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k)) for k in self.get_jwk()['keys']}
        unverified_header = jwt.get_unverified_header(token)
        key_id = unverified_header['kid']
        algorithm = unverified_header['alg']
        public_key = keys[key_id]
        # Check and raise an error if the token verification/validation has some errors(i.e is expired, invalid audience).
        decoded_token = jwt.decode(token, public_key, algorithms=algorithm,
                                   issuer=self.issuer, audience=self.client_id,
                                   require_exp=True, require_iat=True)

        known_nonce = session.get(AUTH_NONCE_KEY)
        stated_nonce = decoded_token[NONCE]
        if verify_nonce and (not known_nonce or not stated_nonce or stated_nonce != known_nonce):
            abort(403, "Invalid nonce value. ")

        return decoded_token

    def get_jwk(self):
        """Get all signing keys that can be used to validate JWT signatures.
        :return: JSON Web Key Set [JWK] document
        """

        response = requests.get(self.jwks_url)
        if response.status_code != 200:
            logging.error('There is no JSON Web Key Set document.')
        response.raise_for_status()
        return response.json()

    @staticmethod
    def is_authenticated():
        return session.get(AUTH_TOKEN_KEY)

    @staticmethod
    def get_token_from_implicit_flow(oauth_session):
        if RESPONSE_URL in request.form:
            stated_state = request.form.get(STATE)
            known_state = session.get(AUTH_STATE_KEY)

            if not known_state or not stated_state or stated_state != known_state:
                abort(403)

            # The full URL of the redirect back to
            url = '{}&expires_in={}&state={}&token_type={}&id_token={}&scope={}'.format(request.form.get(RESPONSE_URL),
                                                                                        request.form.get(EXPIRES_IN),
                                                                                        request.form.get(STATE),
                                                                                        request.form.get(TOKEN_TYPE),
                                                                                        request.form.get(ID_TOKEN),
                                                                                        quote_plus(request.form.get(SCOPE, '')))
            return oauth_session.token_from_fragment(url)
