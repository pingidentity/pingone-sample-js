"""
auth-client
"""
from __future__ import absolute_import, unicode_literals
import logging

__version__ = '0.0.1'

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('oauth-client').addHandler(logging.NullHandler())
