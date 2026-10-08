#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from api.utils.factory import app
from api.database.config import db
from api.utils import config
from api.routes.routes import limiter


class BaseTestCase(unittest.TestCase):
    """A base test case for flask-tracking."""
    def setUp(self):
        with app.app_context():
            app.config.from_object(config.TestingConfig)
            db.create_all()
            # Each test starts with fresh rate limits (login allows 5 per minute).
            limiter.reset()
            self.app = app.test_client()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()
