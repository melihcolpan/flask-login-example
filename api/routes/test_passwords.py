import json

from api.database.config import db
from api.database.models.model_user import User
from api.utils.test_base import BaseTestCase


class PasswordTest(BaseTestCase):

    def post(self, path, payload, headers=None):
        return self.app.post(path, data=json.dumps(payload), content_type='application/json', headers=headers or {})

    def register(self, password, email='pw@example.com', username='pw'):
        return self.post('/v1.0/auth/register', dict(username=username, password=password, email=email))

    def login(self, password, email='pw@example.com'):
        return self.post('/v1.0/auth/login', dict(email=email, password=password))

    def test_password_policy_on_register(self):
        self.assertEqual(self.register('').status_code, 422)
        self.assertEqual(self.register('short').status_code, 422)
        self.assertEqual(self.register(' ' * 10).status_code, 422)
        self.assertEqual(self.register('p' * 5000).status_code, 422)
        self.assertEqual(self.register(12345678).status_code, 422)
        self.assertEqual(self.register('secret-pass', username='   ').status_code, 422)
        self.assertEqual(self.register('secret-pass').status_code, 200)

    def test_password_is_used_exactly_as_typed(self):
        self.assertEqual(self.register('  spaced pass  ').status_code, 200)
        self.assertEqual(self.login('  spaced pass  ').status_code, 200)
        self.assertEqual(self.login('spaced pass').status_code, 401)

    def test_unknown_email_and_wrong_password_get_the_same_answer(self):
        self.assertEqual(self.register('secret-pass').status_code, 200)
        unknown = self.login('secret-pass', email='nobody@example.com')
        wrong = self.login('wrong-pass')
        self.assertEqual(unknown.status_code, 401)
        self.assertEqual(json.loads(unknown.data), json.loads(wrong.data))
        self.assertEqual(self.login('p' * 5000).status_code, 401)

    def test_account_created_with_a_stripped_password_can_still_log_in(self):
        with self.app.application.app_context():
            db.session.add(User(username='old', password='secret-pass', email='old@example.com', user_role='user'))
            db.session.commit()
        self.assertEqual(self.login(' secret-pass ', email='old@example.com').status_code, 200)

    def test_password_change_uses_the_same_policy(self):
        self.assertEqual(self.register('secret-pass').status_code, 200)
        token = json.loads(self.login('secret-pass').data)['value']['access_token']
        headers = {'Authorization': 'Bearer ' + token}

        def change(old, new):
            return self.post('/v1.0/auth/password_change', dict(old_pass=old, new_pass=new), headers)

        self.assertEqual(change('secret-pass', 'short').status_code, 422)
        self.assertEqual(change('secret-pass', None).status_code, 422)
        self.assertEqual(change('wrong-pass', 'new-secret-pass').status_code, 403)
        self.assertEqual(change('secret-pass', ' new secret ').status_code, 200)
        self.assertEqual(self.login(' new secret ').status_code, 200)
