import os
import json
import base64

from flask import Flask

from pymongo import MongoClient
from flask_sslify import SSLify

app = Flask(__name__)
sslify = SSLify(app)

app.config.from_object('econnect.config.Config')

app.debug = False
if 'VCAP_SERVICES' not in os.environ:
    app.debug = True
    app.config.PREFERRED_URL_SCHEME = "http"
    app.config.SERVER_NAME = None


def connect_db():
    prefix = "dev_"
    sufix = "_{}".format(app.config["VERSION"])
    if 'VCAP_SERVICES' in os.environ:
        prefix = ""
        vcap = json.loads(os.getenv('VCAP_SERVICES'))
        print('Found VCAP_SERVICES on environment')
    elif "LOCAL_ENV" in app.config:
        vcap = app.config["LOCAL_ENV"]
        print('Found local VCAP_SERVICES on config')
    else:
        print('No Cloudant')
        return None, None
    if 'compose-for-mongodb' in vcap:
        creds = vcap['compose-for-mongodb'][0]['credentials']
        uri = creds["uri"]
    try:
        ca_certs = base64.b64decode(creds["ca_certificate_base64"])
        with open('cert', 'w') as f:
            f.write(ca_certs.decode("utf-8"))
        client = MongoClient(uri, ssl=True, ssl_ca_certs="cert")
    except:
        raise
        print("Cloudant Error")
    try:
        db = {
            "db_econnect": client["{}econnect{}".format(prefix, sufix)],
            "db_brands": client["{}brands{}".format(prefix, sufix)],
            "db_bots": client["{}bots{}".format(prefix, sufix)],
            "db_users": client["{}users{}".format(prefix, sufix)]
        }
    except:
        raise
        print("Cloudant Error")
    return client, db

# DO NOT MOVE!
from econnect.modules.main import main

app.register_blueprint(main)
