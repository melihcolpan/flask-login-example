#!/usr/bin/python
# -*- coding: utf-8 -*-

from api.utils.factory import app

if __name__ == '__main__':

    # Run app. Debug follows the selected configuration (off by default;
    # enable with APP_CONFIG=development).
    debug = app.config.get('DEBUG', False)
    app.run(port=5000, debug=debug, host='localhost', use_reloader=debug)
