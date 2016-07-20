import json
import unittest

from api import app
from api.models import User
from api.models import db
from api.utils.const import SQLALCHEMY_DATABASE_URI
from flask_testing import TestCase


class MyTest(TestCase):
    def create_app(self):
        app.config['TESTING'] = True
        return app

        # def test_some_json(self):
        #     response = self.client.get("/")
        #     self.assertEquals(response.json, dict(email="bob@gmail.com", user="Bob Jones"))


class DBTest(TestCase):
    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI
    TESTING = True

    def create_app(self):
        # pass in test configuration
        return app

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_something(self):
        user = User(username='sa_username', password='sa_password', email='sa_email@example.com',
                    user_role='super_admin')
        db.session.add(user)
        db.session.commit()
        assert user in db.session


class LoginTest(unittest.TestCase):
    def setUp(self):
        with app.app_context():
            db.create_all()
            user = User(username='sa_username', password='sa_password',
                        email='sa_email@example.com', user_role='super_admin')
            db.session.add(user)
            db.session.commit()
            self.app = app.test_client()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_login(self):
        response = self.app.post("/v1/auth/login",
                                 data=json.dumps(dict(email='sa_email@example.com', password='sa_password')),
                                 content_type='application/json')

        self.assertTrue('access_token' in json.loads(response.data))
        self.assertTrue('refresh_token' in json.loads(response.data))
