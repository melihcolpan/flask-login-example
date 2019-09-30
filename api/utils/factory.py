#!/usr/bin/python
# -*- coding: utf-8 -*-

from api.database.config import db
from api.routes.routes import route_page, limiter
from flask import Flask
from api.utils.config import DevelopmentConfig, ProductionConfig

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)
app.register_blueprint(route_page)

db.init_app(app)
db.app = app
db.create_all()

limiter.init_app(app)
