import json

from api.database.config import db
from api.database.models.model_user import User
from api.utils.test_base import BaseTestCase


class PermissionTest(BaseTestCase):

    def setUp(self):
        super(PermissionTest, self).setUp()
        with self.app.application.app_context():
            for role in ('user', 'admin', 'super_admin'):
                db.session.add(User(username=role, password='secret', email=role + '@example.com', user_role=role))
            db.session.commit()

    def token_for(self, role):
        response = self.app.post('/v1.0/auth/login', content_type='application/json',
                                 data=json.dumps(dict(email=role + '@example.com', password='secret')))
        self.assertEqual(response.status_code, 200)
        return json.loads(response.data)['value']['access_token']

    def get_data(self, header):
        return self.app.get('/v1.0/data', headers={'Authorization': header})

    def test_normal_user_is_denied(self):
        response = self.get_data('Bearer ' + self.token_for('user'))
        self.assertEqual(response.status_code, 403)
        self.assertNotIn('value', json.loads(response.data))

    def test_admin_and_super_admin_are_allowed(self):
        for role in ('admin', 'super_admin'):
            response = self.get_data('Bearer ' + self.token_for(role))
            self.assertEqual(response.status_code, 200, role)
            self.assertEqual(len(json.loads(response.data)['value']), 3)

    def test_missing_or_invalid_tokens_are_rejected(self):
        for header in ('', 'Bearer', 'Bearer not-a-token', 'Basic dXNlcjpwYXNz'):
            self.assertEqual(self.get_data(header).status_code, 401, header)
        self.assertEqual(self.app.get('/v1.0/data').status_code, 401)
