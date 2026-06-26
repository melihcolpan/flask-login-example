#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import create_engine
from api.utils.config import Config

engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)
Base = declarative_base()

# SQLAlchemy 2.0 removed bound MetaData (Base.metadata.bind) and now
# requires an explicit engine for create_all().
Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
session = Session()

db = SQLAlchemy()
