#!/usr/bin/python
# -*- coding: utf-8 -*-

from api import app

if __name__ == '__main__':

    # Run app.
    app.run(port=5000, debug=True, host='localhost', use_reloader=True)
