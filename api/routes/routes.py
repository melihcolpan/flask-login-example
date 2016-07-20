#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging

import api.constants.errors as error
from api.auth import auth, refresh_jwt
from api.models import User, Blacklist
from api.models import db, session, user_schema
from flask import Blueprint
from flask import g, jsonify
from flask import request

route_page = Blueprint("route_page", __name__)


@route_page.before_app_first_request
def setup():
    # Recreate database each time for demo
    User.create(username='sa_username', password='sa_password', email='sa_email@example.com', user_role='super_admin')
    User.create(username='admin_username', password='admin_password', email='admin_email@example.com', user_role='admin')
    User.create(username='test_username', password='test_password', email='test_email@example.com', user_role='user')


@route_page.route('/v1/auth/register', methods=['POST'])
def register():

    try:
        # Get username, password and email.
        username, password, email = request.json.get('username').strip(), request.json.get('password').strip(), \
                                    request.json.get('email').strip()
    except Exception as why:

        # Log input strip or etc. errors.
        logging.info("Username, password or email is wrong. " + str(why))

        # Return invalid input error.
        return jsonify(error.INVALID_INPUT_422)

    # Check if any field is none.
    if username is None or password is None or email is None:
        return jsonify(error.INVALID_INPUT_422)

    # Get user if it is existed.
    user = User.query.filter_by(email=email).first()

    # Check if user is existed.
    if user is not None:
        return jsonify(error.ALREADY_EXIST)

    # Create a new user.
    user = User(username=username, password=password, email=email)

    # Add user to session.
    db.session.add(user)

    # Commit session.
    db.session.commit()

    # Return success if registration is completed.
    return jsonify({'status': 'success'})


@route_page.route('/v1/auth/login', methods=['POST'])
def login():

        try:
            # Get user email and password.
            email, password = request.json.get('email').strip(), request.json.get('password').strip()

            print email, password

        except Exception as why:

            # Log input strip or etc. errors.
            logging.info("Email or password is wrong. " + str(why))

            # Return invalid input error.
            return jsonify(error.INVALID_INPUT_422)

        # Check if user information is none.
        if email is None or password is None:
            return jsonify(error.INVALID_INPUT_422)

        # Get user if it is existed.
        user = User.query.filter_by(email=email, password=password).first()

        # Check if user is not existed.
        if user is None:
            return jsonify(error.DOES_NOT_EXIST)

        print user.user_role

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
            return jsonify(error.PERMISSON_DENIED)

        # Generate refresh token.
        refresh_token = refresh_jwt.dumps({'email': email})

        # Return access token and refresh token.
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token})


@route_page.route('/v1/auth/logout', methods=['POST'])
def logout():

    # Get refresh token.
    refresh_token = request.json.get('refresh_token')

    # Get if the refresh token is in blacklist
    ref = Blacklist.query.filter_by(refresh_token=refresh_token).first()

    # Check refresh token is existed.
    if ref is not None:
        return jsonify({'status': 'already invalidated', 'refresh_token': refresh_token})

    # Create a blacklist refresh token.
    blacklist_refresh_token = Blacklist(refresh_token=refresh_token)

    # Add refresh token to session.
    db.session.add(blacklist_refresh_token)

    # Commit session.
    db.session.commit()

    # Return status of refresh token.
    return jsonify({'status': 'invalidated', 'refresh_token': refresh_token})


@route_page.route('/v1/auth/refresh', methods=['POST'])
def refresh_token():

        # Get refresh token.
        refresh_token = request.json.get('refresh_token')

        # Get if the refresh token is in blacklist.
        ref = Blacklist.query.filter_by(refresh_token=refresh_token).first()

        # Check refresh token is existed.
        if ref is not None:

            # Return invalidated token.
            return jsonify({'status': 'invalidated'})

        try:
            # Generate new token.
            data = refresh_jwt.loads(refresh_token)

        except Exception as why:
            # Log the error.
            logging.error(why)

            # If it does not generated return false.
            return jsonify(False)

        # Create user not to add db. For generating token.
        user = User(email=data['email'])

        # New token generate.
        token = user.generate_auth_token(False)

        # Return new access token.
        return jsonify({'access_token': token})


@route_page.route('/v1/auth/password_reset', methods=['POST'])
def password_reset():

        # Get old and new passwords.
        old_pass, new_pass = request.json.get('old_pass'), request.json.get('new_pass')

        # Get user. g.user generates email address cause we put email address to g.user in models.py.
        user = User.query.filter_by(email=g.user).first()

        # Check if user password does not match with old password.
        if user.password != old_pass:

            # Return does not match status.
            return jsonify({'status': 'old password does not match.'})

        # Update password.
        user.password = new_pass

        # Commit session.
        db.session.commit()

        # Return success status.
        return jsonify({'status': 'password changed.'})


@route_page.route('/data', methods=['GET'])
@auth.login_required
def data_get():

    result = session.query(User).all()
    print result

    print user_schema.dump(result).data

    return jsonify("Data OK.")
