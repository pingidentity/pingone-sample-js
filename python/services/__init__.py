import logging

from services.configuration import Configuration
from services.auth import AuthClient
from services.api_client import ApiClient

__version__ = '0.0.0'

logging.getLogger('ping_oauth_lib').addHandler(logging.NullHandler())
