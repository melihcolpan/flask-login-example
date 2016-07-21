from apispec import APISpec
from api import app
from api.routes import routes
import json

def create_api_spec():

    # Create an APISpec
    spec = APISpec(
        title='Swagger Petstore',
        version='1.0.0',
        plugins=[
            'apispec.ext.flask',
        ],
    )

    ctx = app.test_request_context()
    ctx.push()

    spec.add_path(view=routes.login)
    spec_dict = spec.to_dict()
    return spec_dict

if __name__ == '__main__':
    print json.dumps(create_api_spec())
