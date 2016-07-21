#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask import make_response, jsonify

SERVER_ERROR_500 = {"http_code": 500, "code": "test_stat", "message": "An error occured."}
NOT_FOUND_404 = {"http_code": 404, "code": "test_stat", "message": "Resource could not be found."}
NO_INPUT_400 = {"http_code": 400, "code": "test_stat", "message": "No input data provided."}
INVALID_INPUT_422 = {"http_code": 422, "code": "test_stat", "message": "Invalid input."}
ALREADY_EXIST = {"http_code": 409, "code": "test_stat", "message": "Already exists."}

USER_DOES_NOT_EXIST = {"http_code": 409, "code": "test_stat", "message": "Does not exists."}
NOT_ADMIN = {"http_code": 999, "code": "test_stat", "message": "Admin permission denied."}
HEADER_NOT_FOUND = {"http_code": 999, "code": "test_stat", "message": "Header does not exists."}
PERMISSION_DENIED = {"http_code": 999, "code": "test_stat", "message": "User permissions denied."}
CREDENTIALS_ERROR_999 = {"http_code": 999, "code": "test_stat", "message": "Credentials error."}
MISSED_PARAMETERS = {"http_code": 999, "code": "test_stat", "message": "Missed parameters."}

SUCCESS = {"http_code": 200, "code": "test_stat", "message": "SUCCESS."}
INVALIDATED = {"http_code": 200, "code": "test_stat", "message": "INVALIDATED."}
ALREADY_INVALIDATED = {"http_code": 200, "code": "test_stat", "message": "INVALIDATED."}
OLD_PASS_DOES_NOT_MATCH = {"http_code": 999, "code": "test_stat", "message": "Old password does not match."}
REGISTRATION_COMPLETED = {"http_code": 999, "code": "test_stat", "message": "Old password does not match."}


def m_return(http_code=0, code=None, message=None, value=None):

    my_dict = {}

    if code is not None:
        my_dict['code'] = code

    if message is not None:
        my_dict['message'] = message

    if value is not None:
        my_dict['value'] = value

    # Return response.
    return make_response(jsonify(my_dict), http_code)
