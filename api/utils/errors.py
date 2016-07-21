#!/usr/bin/python
# -*- coding: utf-8 -*-

SERVER_ERROR_500 = {"message": "An error occured.", "code": 500}, 500
NOT_FOUND_404 = {"message": "Resource could not be found.", "code": 404}, 404
NO_INPUT_400 = {"message": "No input data provided.", "code": 400}, 400
INVALID_INPUT_422 = {"message": "Invalid input.", "code": 422}, 422
ALREADY_EXIST = {"message": "Already exists.", "code": 409}, 409

DOES_NOT_EXIST = {"message": "Does not exists.", "code": 409}, 409
NOT_ADMIN = {"message": "Admin permission denied.", "code": 999}, 999
HEADER_NOT_FOUND = {"message": "Header does not exists.", "code": 999}, 999
PERMISSION_DENIED = {"message": "User permissions denied.", "code": 999}, 999
CREDENTIALS_ERROR_999 = {"message": "Credentials error.", "code": 999}, 999
MISSED_PARAMETERS = {"message": "Missed parameters.", "code": 999}, 999

SUCCESS = {"message": "SUCCESS."}, 200
OLD_PASS_DOES_NOT_MATCH = {"message": "Old password does not match.", "code": 999}, 999
