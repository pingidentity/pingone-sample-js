import logging
import logging.config
import os
from datetime import timedelta
from flask import Flask, render_template, url_for, flash, session, redirect, request, Response
from flask_wtf.csrf import CSRFProtect
from requests import HTTPError

from services.api_client import ApiClient
from services.auth import AuthClient

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'

logging.config.fileConfig('logging.ini')

app = Flask(__name__)
app.config.from_pyfile('config.cfg')
app.config.update({'SECRET_KEY': os.urandom(24)})

# Enable CSRF protection globally for a Flask app
csrf = CSRFProtect(app)
auth = AuthClient(app)


@app.before_request
def make_session_permanent():
    session.permanent = True
    # set a session timeout period
    app.permanent_session_lifetime = timedelta(minutes=15)


@app.route('/', endpoint='index')
@csrf.exempt
def index():
    return render_template('index.html')


@app.route('/user/info', methods=['GET'], endpoint='user_info')
@auth.token_required
@csrf.exempt
def user_info():
    try:
        return render_template('index.html', userInfo=auth.get_user_details())
    except HTTPError as e:
        log_error('Could not get user information because of: ', e)
        return render_template('index.html')


@app.route('/callback', methods=['POST'], endpoint='callback_post_access_token')
@auth.callback
def callback():
    """
    Callback for implicit flow to send back access token from user agent.
    It is called from `checkAccessTokenFromUrl' method from 'helpers.js'
    """
    return redirect(url_for('index'))


@app.route('/callback1', methods=['GET'], endpoint='callback')
@auth.callback
@csrf.exempt
def callback():
    return redirect(url_for('index'))


@app.route("/login")
@auth.login_required
def login():
    return render_template('index.html')


@app.route('/logout')
def logout():
    logout_url = auth.get_logout_url()
    if not logout_url:
        logout_url = url_for('index')

    # remove the token from the session if it's there
    session.clear()
    return redirect(logout_url)


@app.route('/password/change', endpoint='change_password', methods=['GET'])
@auth.token_required
@csrf.exempt
def change_password():
    passwords = ApiClient(auth.get_oauth_session(), app)
    password_pattern = passwords.get_user_password_pattern(auth.get_id_token()['sub'])
    return render_template('change_password.html', passwordPattern=password_pattern)


@app.route('/password/change', endpoint='change_password_post', methods=['POST'])
@auth.token_required
def change_password():
    try:
        token = auth.get_id_token()
        passwords = ApiClient(auth.get_oauth_session(), app)
        passwords.change_password(token['sub'], request.form.get('oldPassword'),
                                  request.form.get('password'))
        flash('Password was successfully changed to a new one.', 'success')
        return redirect(url_for('index'))
    except HTTPError as error:
        log_error('Could not change password for the current user because of: ', error)
        return render_template('change_password.html')


@app.errorhandler(Exception)
def handle_error(error):
    if hasattr(error, 'code'):
        if error.code < 400:
            return Response.force_type(error, request.environ)
        elif error.code == 404:
            flash(str(error), 'danger')
            logging.error(str(error))
            return render_template('index.html'), 404
    flash(str(error), 'danger')
    logging.exception('Something went wrong. {}'.format(str(error)))
    return render_template('index.html'), 500


def log_error(message, error):
    error_details = error.response.json().get('details')
    error_msg = error_details[0].get('message') if error_details else error.response.json().get('message')
    flash(message + str(error_msg), 'danger')


if __name__ == "__main__":
    app.run(port=8080, host='localhost', use_debugger=True, use_reloader=True)
