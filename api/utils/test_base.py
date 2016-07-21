import unittest
from api import app
from api.user_model import db
from api.utils import config


class BaseTestCase(unittest.TestCase):
    """A base test case for flask-tracking."""
    def setUp(self):
        with app.app_context():
            app.config.from_object(config.TestingConfig)
            db.create_all()
            self.app = app.test_client()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()
