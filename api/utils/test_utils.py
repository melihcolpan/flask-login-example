from api.utils.test_base import BaseTestCase
from api.utils.spec import create_api_spec


class TestSpec(BaseTestCase):
    def test_spec_creation(self):
        spec = create_api_spec()
        self.assertIsInstance(spec, dict)
