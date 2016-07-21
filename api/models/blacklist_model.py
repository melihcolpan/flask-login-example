#!/usr/bin/python
# -*- coding: utf-8 -*-

from api.utils.database import db


class Blacklist(db.Model):

    # Generates default class name for table. For changing use
    __tablename__ = 'blacklist'

    # Blacklist id.
    id = db.Column(db.Integer, primary_key=True)

    # Blacklist invalidated refresh tokens.
    refresh_token = db.Column(db.String(length=255))

    def __repr__(self):

        # This is only for representation how you want to see refresh tokens after query.
        return "<User(id='%s', refresh_token='%s', status='invalidated.')>" % (
                      self.id, self.refresh_token)
