#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging

import api.utils.responses as resp
from api.models.user_model import User
from api.models.blacklist_model import Blacklist
from api.models.user_model import UserSchema
from api.utils.database import session
from api.utils.auth import auth, refresh_jwt
from api.utils.database import db
from api.utils.responses import m_return
from flask import Blueprint
from flask import g
from flask import request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from passlib.handlers.md5_crypt import md5_crypt
from api.utils.decorators import permission


route_page = Blueprint("route_page", __name__)

limiter = Limiter(key_func=get_remote_address)


@route_page.before_app_first_request
def setup():
    # Recreate database each time for demo
    User.create(username='sa_username', password='sa_password', email='sa_email@example.com', user_role='super_admin')
    User.create(username='admin_username', password='admin_password', email='admin_email@example.com',
                user_role='admin')
    User.create(username='test_username', password='test_password', email='test_email@example.com', user_role='user')
    print "Default users added."


@route_page.after_request
def add_header(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['ABC-Header-Melih'] = ':)'
    return response


@route_page.route('/v1.0/auth/register', methods=['POST'])
def register():

    try:
        # Get username, password and email.
        username, password, email = request.json.get('username').strip(), request.json.get('password').strip(), \
                                    request.json.get('email').strip()
    except Exception as why:

        # Logging the error.
        logging.warning(why)

        # Return missed parameter error.
        return m_return(http_code=resp.MISSED_PARAMETERS['http_code'], message=resp.MISSED_PARAMETERS['message'],
                        code=resp.MISSED_PARAMETERS['code'])

    # Create a new user.
    user = User.create(username=username, password=password, email=email, user_role='user')

    # Check if user is already existed.
    if user is None:

        # Return already exists error.
        return m_return(http_code=resp.ALREADY_EXIST['http_code'], message=resp.ALREADY_EXIST['message'],
                        code=resp.ALREADY_EXIST['code'])

    # User schema for some fields.
    user_schema = UserSchema(only=('id', 'username', 'email', 'created', 'user_role'))

    # Return registration completed.
    return m_return(http_code=resp.REGISTRATION_COMPLETED['http_code'], message=resp.REGISTRATION_COMPLETED['message'],
                    value=user_schema.dump(user).data)


@route_page.route('/v1.0/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():

        try:
            # Get user email and password. Was not checked cause none type has no attribute strip.
            email, password = request.json.get('email').strip(), request.json.get('password').strip()

        except Exception as why:

            # Log input strip or etc. errors.
            logging.info("Email or password is wrong. " + str(why))

            # Return invalid input error. Response 0 is message, 1 is http response http_code.
            return m_return(http_code=resp.MISSED_PARAMETERS['http_code'], message=resp.MISSED_PARAMETERS['message'],
                            code=resp.MISSED_PARAMETERS['code'])

        # Get user if it is existed.
        user = User.query.filter_by(email=email).first()

        # Check if user is not existed.
        if user is None:

            # Return error message.
            return m_return(http_code=resp.USER_DOES_NOT_EXIST['http_code'],
                            message=resp.USER_DOES_NOT_EXIST['message'],
                            code=resp.USER_DOES_NOT_EXIST['code'])

        # User password verify.
        if not user.verify_password_hash(password):

            # Return error message.
            return m_return(http_code=resp.CREDENTIALS_ERROR_999['http_code'],
                            message=resp.CREDENTIALS_ERROR_999['message'], code=resp.CREDENTIALS_ERROR_999['code'])

        # Check if user does not have admin or super admin permissions.
        if user.user_role == 'user':

            # Generate access token. This method takes boolean value for checking admin or normal user. Admin: 1 or 0.
            access_token = user.generate_auth_token(0)

        # If user is admin.
        elif user.user_role == 'admin':

            # Generate access token. This method takes boolean value for checking admin or normal user. Admin: 1 or 0.
            access_token = user.generate_auth_token(1)

        # If user is super admin.
        elif user.user_role == 'super_admin':

            # Generate access token. This method takes boolean value for checking admin or normal user. Admin: 2, 1, 0.
            access_token = user.generate_auth_token(2)

        else:

            # Return permission denied error.
            return m_return(http_code=resp.PERMISSION_DENIED['http_code'], message=resp.PERMISSION_DENIED['message'],
                            code=resp.PERMISSION_DENIED['code'])

        # Generate refresh token.
        m_refresh_token = refresh_jwt.dumps({'email': email})

        # Return access token and refresh token.
        return m_return(http_code=resp.SUCCESS['http_code'],
                        message=resp.SUCCESS['message'],
                        value={'access_token': access_token, 'refresh_token': m_refresh_token})


@route_page.route('/v1.0/auth/logout', methods=['POST'])
@auth.login_required
def logout():

    try:
        # Get refresh token.
        m_refresh_token = request.json.get('refresh_token')

    except Exception as why:

        # Logging the error.
        logging.warning(why)

        # Return invalid input error.
        return m_return(http_code=resp.INVALID_INPUT_422['http_code'], message=resp.INVALID_INPUT_422['message'],
                        code=resp.INVALID_INPUT_422['code'])

    # Get if the refresh token is in blacklist
    ref = Blacklist.query.filter_by(refresh_token=m_refresh_token).first()

    # Check refresh token is existed.
    if ref is not None:

        # Return this refresh token is already invalidated.
        return m_return(http_code=resp.ALREADY_INVALIDATED['http_code'], message=resp.ALREADY_INVALIDATED['message'],
                        code=resp.ALREADY_INVALIDATED['code'])

    # Create a blacklist refresh token.
    blacklist_refresh_token = Blacklist(refresh_token=m_refresh_token)

    # Add refresh token to session.
    db.session.add(blacklist_refresh_token)

    # Commit session.
    db.session.commit()

    # Return status of refresh token.
    return m_return(http_code=resp.SUCCESS['http_code'], message=resp.SUCCESS['message'], value={})


@route_page.route('/v1.0/auth/refresh', methods=['POST'])
def refresh_token():

    try:
        # Get refresh token.
        m_refresh_token = request.json.get('refresh_token')

    except Exception as why:

        # Logging the error.
        logging.warning(why)

        # Return missed parameters.
        return m_return(http_code=resp.MISSED_PARAMETERS['http_code'], message=resp.MISSED_PARAMETERS['message'],
                        code=resp.MISSED_PARAMETERS['code'])

    # Get if the refresh token is in blacklist.
    ref = Blacklist.query.filter_by(refresh_token=m_refresh_token).first()

    # Check refresh token is existed.
    if ref is not None:

        # Return this refresh token is already invalidated.
        return m_return(http_code=resp.ALREADY_INVALIDATED['http_code'], message=resp.ALREADY_INVALIDATED['message'],
                        code=resp.ALREADY_INVALIDATED['code'])

    try:
        # Generate new token.
        data = refresh_jwt.loads(m_refresh_token)

    except Exception as why:

        # Log the error.
        logging.error(why)

        # If it does not generated return false.
        # Return this refresh token is already invalidated.
        return m_return(http_code=resp.CREDENTIALS_ERROR_999['http_code'],
                        message=resp.CREDENTIALS_ERROR_999['message'], code=resp.CREDENTIALS_ERROR_999['code'])

    # Create user not to add db. For generating token.
    user = User(email=data['email'])

    # New token generate.
    token = user.generate_auth_token(0)

    # Return new access token.
    return m_return(http_code=resp.SUCCESS['http_code'], message=resp.SUCCESS['message'], value={'access_token': token})


@route_page.route('/v1.0/auth/password_change', methods=['POST'])
@auth.login_required
def password_change():

        # Get old and new passwords.
        old_pass, new_pass = request.json.get('old_pass'), request.json.get('new_pass')

        # Get user. g.user generates email address cause we put email address to g.user in models.py.
        user = User.query.filter_by(email=g.user).first()

        # Check if user password does not match with old password.
        if not user.verify_password_hash(old_pass):

            # Return does not match status.
            return m_return(http_code=resp.OLD_PASS_DOES_NOT_MATCH['http_code'],
                            message=resp.OLD_PASS_DOES_NOT_MATCH['message'], code=resp.OLD_PASS_DOES_NOT_MATCH['code'])

        # Update password.
        user.password = md5_crypt.encrypt(new_pass)

        # Commit session.
        db.session.commit()

        # Return success status.
        return m_return(http_code=resp.SUCCESS['http_code'], message=resp.SUCCESS['message'], value={})


@route_page.route('/data', methods=['GET'])
@auth.login_required
@permission(1)
@limiter.limit("100 per day")
def data_get():

    # ONLY ADMIN AND SUPER ADMIN!
    # User schema for some fields.
    user_schema = UserSchema(only=('id', 'username', 'email', 'created', 'user_role'))

    # Get all users from database.
    result = session.query(User).all()

    # Dumps database objects to json.
    users = user_schema.dump(result).data

    # Return users.
    return m_return(http_code=resp.SUCCESS['http_code'], message=resp.SUCCESS['message'], value=users)
