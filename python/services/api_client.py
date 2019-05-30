import re

from .configuration import Configuration

__all__ = 'ApiClient'


class ApiClient(Configuration):

    def __init__(self, oauth_session, app):
        """
        :param oauth_session: instance of OAuth 2 extension to :class:`requests_oauthlib.OAuth2Session`.
        :param app: flask application
        """
        Configuration.__init__(self, app.config)
        self.oauth_session = oauth_session

    def get_user_password_pattern(self, user_id):
        default_password_policy = self.get_user_password_policy(user_id)
        return self.get_password_pattern_from_policy(default_password_policy)

    def get_user_password_policy(self, user_id):
        password_policies = self.oauth_session.get('{}/users/{}/password?expand=passwordPolicy'.format(self.environment_url, user_id))
        password_policies.raise_for_status()  # throw exception if request does not return 2xx
        return password_policies.json()['_embedded']['passwordPolicy']

    def change_password(self, user_id, current_password, new_password):
        headers = {
            'Content-Type': 'application/vnd.pingidentity.password.reset+json'
        }
        data = {
            'currentPassword': current_password,
            'newPassword': new_password
        }
        response = self.oauth_session.put(
            '{}/users/{}/password'.format(self.environment_url, user_id),
            json=data, headers=headers)
        response.raise_for_status()
        return response

    @staticmethod
    def get_password_pattern_from_policy(password_policy):
        # Get password validation pattern(regex) based by policy
        # Example: ^(?:(?=(?:.*[ABCDEFGHIZ]){3,4})(?=(?:.*[123456890]){1,4})(?=.*[abcdefghijklmnopqrstuvwxyz])(?=(?:.*[~!@#\$%\^&\*\(\)\-_=\+\[\]\{\}\|;:,\.<>/\?]){1,4}))(?!.*(.)\1{3,}).{6,20}$
        # ^                         start of the password
        # (?:                       non-capturing group to assert the whole password phrase
        # (?=                       lookahead assertion for the following group of characters
        # (?:.*[ABCDEFGHIZ]){3, 4}) must contains from 3 to 4 uppercase characters
        #     .....
        # (?!.*(.)\1 {3, })         allow up to three repeated characters
        # .                         match anything with previous condition checking
        # {6, 20}                   length at least 6 characters and maximum of 20
        # $                         the end of the password
        #
        # NOTE: Unlike Standard C, all unrecognized escape sequences are left in the string unchanged, i.e., the backslash is left in the result.
        # See https://docs.python.org/3/reference/lexical_analysis.html#string-and-bytes-literals
        # See https://www.regular-expressions.info/python.html
        # See https://www.rexegg.com/regex-lookarounds.html#password for better understanding some parts in this regex

        password_pattern = '^(?:'
        # Construct lookahead assertion for each policy "minCharacters" group
        for pattern, number in password_policy.get('minCharacters').items():
            # Escape all special for javascript characters
            password_pattern += '(?=(?:.*[' + \
                                re.sub('[\\{\\}\\(\\)\\[\\]\\.\\+\\*\\?\\^\\$\\\\|-]',
                                       #   inserts the entire regex match of the capturing group
                                       r'\\\g<0>',
                                       pattern) + ']){'
            password_pattern += str(number) + ',})'

        password_pattern += ')'
        # Set how many consecutive characters are allowed
        password_pattern += '(?!.*(.)\\1{' + str(password_policy.get('maxRepeatedCharacters')) + ',})'
        # Set how many characters password should have
        password_pattern += '.{' + str(password_policy.get('length').get('min')) + ',' + str(
            password_policy.get('length').get('max'))
        password_pattern += '}$'

        return password_pattern
