import json

from api.database.config import db
from api.database.models.model_user import User
from api.utils.test_base import BaseTestCase


class DBTest(BaseTestCase):

    def test_user_create(self):
        with self.app.application.app_context():
            user = User(username='sa_username', password='sa_password',
                        email='sa_email@example.com', user_role='super_admin')
            db.session.add(user)
            db.session.commit()
            assert user in db.session

    def test_password_hash(self):
        user = User(username='sa_username', password='sa_password',
                    email='sa_email@example.com', user_role='super_admin')
        # The stored value must be a hash, not the plaintext password.
        self.assertNotEqual(user.password, "sa_password")
        self.assertTrue(user.verify_password_hash("sa_password"))
        self.assertFalse(user.verify_password_hash("wrong_password"))


class LoginTest(BaseTestCase):

    def setUp(self):
        super(LoginTest, self).setUp()
        with self.app.application.app_context():
            user = User(username='test_user', password='test_password',
                        email='test@example.com', user_role='user')
            db.session.add(user)
            db.session.commit()

    def test_login(self):
        response = self.app.post("/v1.0/auth/login",
                                 data=json.dumps(
                                     dict(email='test@example.com', password='test_password')),
                                 content_type='application/json')
        data = json.loads(response.data)

        self.assertEqual(response.status_code, 200)
        # Tokens are returned under the "value" key by m_return().
        self.assertIn('access_token', data.get('value'))
        self.assertIn('refresh_token', data.get('value'))
