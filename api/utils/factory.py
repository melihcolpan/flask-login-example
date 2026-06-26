#!/usr/bin/python
# -*- coding: utf-8 -*-

import os

from api.database.config import db
from api.routes.routes import route_page, limiter
from flask import Flask
from api.utils.config import DevelopmentConfig, ProductionConfig, TestingConfig

# Pick the configuration from APP_CONFIG, defaulting to the safe production
# config (debug off). Set APP_CONFIG=development while working locally.
_CONFIGS = {
    "production": ProductionConfig,
    "development": DevelopmentConfig,
    "testing": TestingConfig,
}
config_name = os.environ.get("APP_CONFIG", "production").lower()

app = Flask(__name__)
app.config.from_object(_CONFIGS.get(config_name, ProductionConfig))

# A real secret key is required; refuse to start with an empty one.
if not app.config.get("SECRET_KEY"):
    raise RuntimeError(
        "SECRET_KEY environment variable must be set. "
        "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
    )

app.register_blueprint(route_page)

db.init_app(app)

# Flask-SQLAlchemy 3.x removed db.app; create tables within an app context.
with app.app_context():
    db.create_all()

limiter.init_app(app)
