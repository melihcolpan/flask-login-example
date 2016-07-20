#!/usr/bin/python
# -*- coding: utf-8 -*-

from datetime import datetime

from api.auth import jwt, auth
from api.constants.const import SQLALCHEMY_DATABASE_URI
from flask import g
from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import ModelSchema
from sqlalchemy import Enum
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


engine = create_engine(SQLALCHEMY_DATABASE_URI)
Base = declarative_base()
db = SQLAlchemy()

Base.metadata.bind = engine
Base.metadata.create_all()

Session = sessionmaker(bind=engine)
session = Session()


class User(db.Model):

    # Generates default class name for table. For changing use
    # __tablename__ = 'users'

    # User id.
    id = db.Column(db.Integer, primary_key=True)

    # User name.
    username = db.Column(db.String(length=80))

    # User password.
    password = db.Column(db.String(length=80))

    # User email address.
    email = db.Column(db.String(length=80))

    # Creation time for user.
    created = db.Column(db.DateTime, default=datetime.utcnow)

    # Unless otherwise stated default role is user.
    user_role = db.Column(db.String, Enum('super_admin', 'admin', 'user', name='user_roles'), default='user')

    # Generates auth token.
    def generate_auth_token(self, permission_level):

        # Check if admin.
        if permission_level == 2:

            # Generate admin token with flag 1.
            token = jwt.dumps({'email': self.email, 'admin': 2})

            # Return admin flag.
            return token

            # Check if admin.
        elif permission_level == 1:

            # Generate admin token with flag 1.
            token = jwt.dumps({'email': self.email, 'admin': 1})

            # Return admin flag.
            return token

        # Return normal user flag.
        return jwt.dumps({'email': self.email, 'admin': 0})

    # Generates a new access token from refresh token.
    @staticmethod
    @auth.verify_token
    def verify_auth_token(token):

        # Create a global none user.
        g.user = None

        try:
            # Load token.
            data = jwt.loads(token)

        except:
            # If any error return false.
            return False

        # Check if email and admin permission variables are in jwt.
        if 'email' and 'admin' in data:

            # Set email from jwt.
            g.user = data['email']

            # Set admin permission from jwt.
            g.admin = data['admin']

            # Return true.
            return True

        # If does not verified, return false.
        return False

    # Creates a new user.
    @staticmethod
    def create(username, password, email, user_role):

        # Check if admin is existed in db.
        user = User.query.filter_by(email=email).first()

        # If user is none.
        if user is None:

            # Check user parameters.
            if username is None or password is None or email is None or user_role is None:
                # Print missed parameter.
                print "User was not added cause parameter missed."

                # Do nothing.
                return

            # Create admin user if it does not existed.
            user = User(username=username, password=password, email=email, user_role=user_role)

            # Add user to session.
            db.session.add(user)

            # Commit session.
            db.session.commit()

            # Print admin user status.
            return ("User was set.")

        else:

            # Print admin user status.
            print("User already set.")

    def __repr__(self):

        # This is only for representation how you want to see user information after query.
        return "<User(id='%s', name='%s', password='%s', email='%s', created='%s')>" % (
                      self.id, self.username, self.password, self.email, self.created)


class UserSchema(ModelSchema):
    class Meta:
        model = User
user_schema = UserSchema(many=True)


class Blacklist(db.Model):

    # Generates default class name for table. For changing use
    # __tablename__ = 'users'

    # Blacklist id.
    id = db.Column(db.Integer, primary_key=True)

    # Blacklist invalidated refresh tokens.
    refresh_token = db.Column(db.String(length=255))

    def __repr__(self):

        # This is only for representation how you want to see refresh tokens after query.
        return "<User(id='%s', refresh_token='%s', status='invalidated.')>" % (
                      self.id, self.refresh_token)
