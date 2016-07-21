#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask_httpauth import HTTPTokenAuth
from itsdangerous import TimedJSONWebSignatureSerializer as m_JWT

# JWT creation.
jwt = m_JWT('top secret!', expires_in=3600)

# Refresh token creation.
refresh_jwt = m_JWT('telelelele', expires_in=7200)

# Auth object creation.
auth = HTTPTokenAuth('Bearer')
