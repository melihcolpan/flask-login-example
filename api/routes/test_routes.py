from api.utils.database import db
from api.models.user_model import User
import json
from api.utils.test_base import BaseTestCase


class DBTest(BaseTestCase):

    def test_user_create(self):
        user = User(username='sa_username', password='sa_password',
                    email='sa_email@example.com', user_role='super_admin')
        db.session.add(user)
        db.session.commit()
        assert user in db.session

    def test_md5_encrypt(self):
        user = User(username='sa_username', password='sa_password',
                    email='sa_email@example.com', user_role='super_admin')
        self.assertTrue(user.verify_password_hash("sa_password"))


class LoginTest(BaseTestCase):

    def setUp(self):
        super(LoginTest, self).setUp()
        user = User(username='test_user', password='test_password',
                    email='test@example.com', user_role='user')
        db.session.add(user)
        db.session.commit()

    def test_login(self):
        response = self.app.post("/v1/auth/login",
                                 data=json.dumps(
                                     dict(email='test@example.com', password='test_password')),
                                 content_type='application/json')
        data = json.loads(response.data)

        self.assertEqual(response.status_code, 200) 
        self.assertTrue('access_token' in data.get('message'))
        self.assertTrue('refresh_token' in data.get('message'))
