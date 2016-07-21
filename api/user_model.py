#!/usr/bin/python
# -*- coding: utf-8 -*-

from datetime import datetime

from api.auth import jwt, auth
from api.utils.const import SQLALCHEMY_DATABASE_URI
from flask import g, jsonify
from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import ModelSchema
from sqlalchemy import Enum
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import api.utils.responses as error
import logging

from passlib.handlers.md5_crypt import md5_crypt


engine = create_engine(SQLALCHEMY_DATABASE_URI)
Base = declarative_base()
db = SQLAlchemy()

Base.metadata.bind = engine
Base.metadata.create_all()

Session = sessionmaker(bind=engine)
session = Session()


class User(db.Model):

    # Generates default class name for table. For changing use
    __tablename__ = 'users'

    # __table_args__ = (db.UniqueConstraint('email'),)

    # User id.
    id = db.Column(db.Integer, primary_key=True)

    # User name.
    username = db.Column(db.String(length=80), nullable=False)

    # User password.
    password = db.Column(db.String(length=80), nullable=False)

    # User email address.
    email = db.Column(db.String(length=80), unique=True, nullable=False)

    # Creation time for user.
    created = db.Column(db.DateTime, default=datetime.utcnow)

    # Unless otherwise stated default role is user.
    user_role = db.Column(db.String, Enum('super_admin', 'admin', 'user', name='user_roles'), default='user')

    def as_dict(self):
        return {'username': self.username, 'email': self.email, 'created': self.created, 'user_role': self.user_role}

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
        if 'email' in data and 'admin' in data:

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
    def create(username, password, email, user_role='user'):

        try:
            # Create admin user if it does not existed.
            user = User(username=username, password=md5_crypt.encrypt(password), email=email, user_role=user_role)

            # Add user to session.
            db.session.add(user)

            # Commit session.
            db.session.commit()

            # Print admin user status.
            return user

        except IntegrityError as why:

            # Logging the error.
            logging.warning(why)

            # Return none if there is email unique constraint error.
            return None

        except Exception as why:

            # Logging the generic errors.
            logging.warning(why)

            # Return error.
            return None


    @staticmethod
    def generate_password_hash(password):

        # Generate password hash.
        hash = md5_crypt.encrypt(password)

        # Return hash.
        return hash

    def verify_password_hash(self, password):

        # Return result of verifying password, true or false.
        return md5_crypt.verify(password, self.password)

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
