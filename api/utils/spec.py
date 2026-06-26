#!/usr/bin/python
# -*- coding: utf-8 -*-

from apispec import APISpec
from apispec_webframeworks.flask import FlaskPlugin
from api.utils.factory import app
from api.routes import routes
import json


def create_api_spec():

    # Create an APISpec. apispec 1.0+ takes plugin instances (the Flask
    # plugin moved to the apispec-webframeworks package) and requires a
    # full openapi_version.
    spec = APISpec(
        title='Swagger Petstore',
        version='1.0.0',
        plugins=[FlaskPlugin()],
        openapi_version='2.0'
    )

    with app.test_request_context():
        # apispec 1.0+ renamed add_path() to path().
        spec.path(view=routes.login)

    return spec.to_dict()


if __name__ == '__main__':
    print(json.dumps(create_api_spec()))
