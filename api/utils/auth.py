#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask_httpauth import HTTPTokenAuth
from itsdangerous import URLSafeTimedSerializer


class TimedToken:
    """Signed, expiring token serializer.

    itsdangerous 2.x removed TimedJSONWebSignatureSerializer. This wraps
    URLSafeTimedSerializer to keep the dumps()/loads() interface the rest of
    the code relies on; loads() rejects tokens older than ``expires_in``
    seconds by raising itsdangerous.SignatureExpired.
    """

    def __init__(self, secret, expires_in):
        self.serializer = URLSafeTimedSerializer(secret)
        self.expires_in = expires_in

    def dumps(self, data):
        return self.serializer.dumps(data)

    def loads(self, token):
        return self.serializer.loads(token, max_age=self.expires_in)


# JWT creation.
jwt = TimedToken('top secret!', expires_in=3600)

# Refresh token creation.
refresh_jwt = TimedToken('telelelele', expires_in=7200)

# Auth object creation.
auth = HTTPTokenAuth('Bearer')
