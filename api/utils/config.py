#!/usr/bin/python
# -*- coding: utf-8 -*-

import os


class Config(object):
    DEBUG = False
    TESTING = False
    # Flask secret key, read from the environment. Never hardcode this.
    SECRET_KEY = os.environ.get("SECRET_KEY")
    # Database URL, overridable via env (defaults to a local SQLite file).
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URI", "sqlite:////tmp/test.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class ProductionConfig(Config):
    pass


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite://"
