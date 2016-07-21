#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging

import api.utils.responses as resp
from api.utils.responses import m_return
from api.auth import auth, refresh_jwt
from api.user_model import User, Blacklist
from api.user_model import db, session, user_schema
from flask import Blueprint
from flask import g, jsonify, make_response
from flask import request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from passlib.handlers.md5_crypt import md5_crypt


route_page = Blueprint("route_page", __name__)

limiter = Limiter(key_func=get_remote_address)


@route_page.before_app_first_request
def setup():
    # Recreate database each time for demo
    User.create(username='sa_username', password='sa_password', email='sa_email@example.com', user_role='super_admin')
    User.create(username='admin_username', password='admin_password', email='admin_email@example.com', user_role='admin')
    User.create(username='test_username', password='test_password', email='test_email@example.com', user_role='user')
    print "Default users added."


@route_page.route('/v1/auth/register', methods=['POST'])
def register():

    try:
        # Get username, password and email.
        username, password, email = request.json.get('username').strip(), request.json.get('password').strip(), \
                                    request.json.get('email').strip()
    except Exception as why:

        # Logging the error.
        logging.warning(why)

        # Return missed parameter error. Response 0 is message, 1 is http response code.
        return m_return(resp.MISSED_PARAMETERS[0], resp.MISSED_PARAMETERS[1])

    # Create a new user.
    user = User.create(username=username, password=password, email=email, user_role='user')

    # Check if user is already existed.
    if user is None:

        # Return error. Response 0 is message, 1 is http response code.
        return m_return(resp.ALREADY_EXIST[0], resp.ALREADY_EXIST[1])

    # Return success if registration is completed. Response 0 is message, 1 is http response code.
    return m_return(resp.SUCCESS[0], resp.SUCCESS[1])


@route_page.route('/v1/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():

        try:
            # Get user email and password. Was not checked cause none type has no attribute strip.
            email, password = request.json.get('email').strip(), request.json.get('password').strip()

        except Exception as why:

            # Log input strip or etc. errors.
            logging.info("Email or password is wrong. " + str(why))

            # Return invalid input error. Response 0 is message, 1 is http response code.
            return m_return(resp.INVALID_INPUT_422[0], resp.INVALID_INPUT_422[1])

        # Get user if it is existed.
        user = User.query.filter_by(email=email).first()

        # Check if user is not existed.
        if user is None:

            # Return error message.
            return m_return(resp.DOES_NOT_EXIST[0], resp.DOES_NOT_EXIST[1])

        # User password verify.
        if not user.verify_password_hash(password):

            # Return error message.
            return m_return(resp.CREDENTIALS_ERROR_999[0], resp.CREDENTIALS_ERROR_999[1])

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
            return m_return(resp.PERMISSION_DENIED[0], resp.PERMISSION_DENIED[1])

        # Generate refresh token.
        m_refresh_token = refresh_jwt.dumps({'email': email})

        # Return access token and refresh token.
        return m_return({'access_token': access_token, 'refresh_token': m_refresh_token}, resp.SUCCESS[1])


@route_page.route('/v1/auth/logout', methods=['POST'])
@auth.login_required
def logout():

    try:
        # Get refresh token.
        m_refresh_token = request.json.get('refresh_token')

    except Exception as why:

        # Logging the error.
        logging.warning(why)

        # Return invalid input error.
        return m_return(resp.INVALID_INPUT_422[0], resp.INVALID_INPUT_422[1])

    # Get if the refresh token is in blacklist
    ref = Blacklist.query.filter_by(refresh_token=m_refresh_token).first()

    # Check refresh token is existed.
    if ref is not None:
        return m_return({'status': 'already invalidated', 'refresh_token': m_refresh_token}, 200)

    # Create a blacklist refresh token.
    blacklist_refresh_token = Blacklist(refresh_token=m_refresh_token)

    # Add refresh token to session.
    db.session.add(blacklist_refresh_token)

    # Commit session.
    db.session.commit()

    # Return status of refresh token.
    return m_return({'status': 'invalidated', 'refresh_token': m_refresh_token}, 200)


@route_page.route('/v1/auth/refresh', methods=['POST'])
def refresh_token():

    try:
        # Get refresh token.
        m_refresh_token = request.json.get('refresh_token')

    except Exception as why:

        # Logging the error.
        logging.warning(why)

        return m_return(resp.INVALID_INPUT_422[0], resp.INVALID_INPUT_422[1])

    # Get if the refresh token is in blacklist.
    ref = Blacklist.query.filter_by(refresh_token=m_refresh_token).first()

    # Check refresh token is existed.
    if ref is not None:

        # Return invalidated token.
        return  m_return(resp.ALREADY_INVALIDATED[0], resp.ALREADY_INVALIDATED[1])

    try:
        # Generate new token.
        data = refresh_jwt.loads(m_refresh_token)

    except Exception as why:

        # Log the error.
        logging.error(why)

        # If it does not generated return false.
        return m_return(resp.CREDENTIALS_ERROR_999[0], resp.CREDENTIALS_ERROR_999[1])

    # Create user not to add db. For generating token.
    user = User(email=data['email'])

    # New token generate.
    token = user.generate_auth_token(0)

    # Return new access token.
    return m_return({'access_token': token}, 200)


@route_page.route('/v1/auth/password_reset', methods=['POST'])
@auth.login_required
def password_reset():

        # Get old and new passwords.
        old_pass, new_pass = request.json.get('old_pass'), request.json.get('new_pass')

        # Get user. g.user generates email address cause we put email address to g.user in models.py.
        user = User.query.filter_by(email=g.user).first()

        # Check if user password does not match with old password.
        if not user.verify_password_hash(old_pass):

            # Return does not match status.
            return m_return(resp.OLD_PASS_DOES_NOT_MATCH[0], resp.OLD_PASS_DOES_NOT_MATCH[1])

        # Update password.
        user.password = md5_crypt.encrypt(new_pass)

        # Commit session.
        db.session.commit()

        # Return success status.
        return m_return(resp.SUCCESS[0], resp.SUCCESS[1])


@route_page.route('/data', methods=['GET'])
@auth.login_required
@limiter.limit("100 per day")
def data_get():

    result = session.query(User).all()
    print result

    print user_schema.dump(result).data

    # return make_response(jsonify(error.PERMISSION_DENIED['message']), error.PERMISSION_DENIED['code'])
    return m_return('test', 999)
