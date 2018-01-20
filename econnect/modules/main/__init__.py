import random
import logging
import requests

from flask import g
from flask import flash
from flask import abort
from flask import url_for
from flask import request
from flask import redirect
from flask import Blueprint
from flask import render_template

from flask_login import login_user
from flask_login import logout_user
from flask_login import current_user
from flask_login import LoginManager
from flask_login import login_required

from urllib.parse import urlparse
from urllib.parse import urljoin

from econnect import app
from econnect import connect_db


main = Blueprint('main', __name__)

econnect_logger = logging.getLogger('eConnect')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'mongo_db'):
        g.mongo_client, g.mongo_db = connect_db()
    return g.mongo_db


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'mongo_db'):
        if g.mongo_client is not None:
            g.mongo_client.close()


class user_class():
    def __init__(self, username, user_id=None):
        self.is_authenticated = False
        self.is_active = True
        self.is_anonymous = False

        self.username = username
        self.user_id = user_id

        self.load()

    def check_autentication(self, username, password):
        db = get_db()
        query = {"username": username}
        print(query)
        user = db["db_users"]["users"].find_one(query)
        print(user)
        if user is not None:
            if str(user["password"]) == "123":
                self.is_authenticated = True
                self.user_id = user["uuid"]
                print("AUTH")
                update = {
                    "$set": {
                        "authenticated": self.is_authenticated
                    }
                }
                # user.update(update)
                db["db_users"]["users"].update_one(query, update)

    def load(self):
        if self.user_id is None:
            return
        db = get_db()
        query = {"uuid": self.user_id}
        print(query)
        user = db["db_users"]["users"].find_one(query)
        print(user)
        if user is None:
            return
        self.is_authenticated = user["authenticated"]
        self.username = user["username"]

    def get_id(self):
        return str(self.user_id)

    def get_bots(self):
        db = get_db()
        query = {"owners": {"$elemMatch": {"$eq": self.user_id}}}
        bots = db["db_bots"]["bots"].find(query)
        return bots

    def get_facebook_auth_state(self, new=False):
        db = get_db()
        query = {"uuid": self.user_id}
        user = db["db_users"]["users"].find_one(query)
        state = None
        if new:
            state = str(random.randint(1000, 9999))
            update = {
                "$set": {
                    "facebook_auth_state": state
                }
            }
            db["db_users"]["users"].update_one(query, update)
        else:
            state = user["facebook_auth_state"]
        return state

    def get_facebook_user(self):
        db = get_db()
        query = {"uuid": self.user_id}
        user = db["db_users"]["users"].find_one(query)
        if user["facebook_user"] is None:
            return None
        facebook_access_token = user["facebook_user"]["facebook_access_token"]
        facebook_user_id = user["facebook_user"]["facebook_user_id"]

        params = {
            "access_token": facebook_access_token
        }
        url = "https://graph.facebook.com/v2.11/me?fields=first_name,accounts"
        r = requests.get(url, params=params)
        r_json = r.json()
        if "error" in r_json:
            return None

        facebook_pages = []
        for facebook_page in r_json["accounts"]["data"]:
            if "ADMINISTER" in facebook_page["perms"]:
                params = {
                    "access_token": facebook_access_token
                }
                url = "https://graph.facebook.com/v2.11/{}?fields=connected_instagram_account".format(facebook_page["id"])
                r = requests.get(url, params=params)
                rr_json = r.json()
                if "error" in rr_json:
                    return None
                data = {
                    "name": facebook_page["name"],
                    "id": facebook_page["id"],
                    "instagram": rr_json.get("connected_instagram_account", None),
                    "subscripted_app": False,
                    "subscripbed_to_facebook": False,
                    "subscripbed_to_messenger": False,
                    "subscripbed_to_instagram": False,
                }
                params = {
                    "access_token": facebook_page["access_token"]
                }
                url = "https://graph.facebook.com/v2.11/{}/subscribed_apps".format(facebook_page["id"])
                r = requests.get(url, params=params)
                rr_json = r.json()
                print(r.text)
                if "error" in rr_json:
                    return None
                for subscription in rr_json["data"]:
                    if subscription["id"] == app.config["FB_APP_ID"]:
                        data["subscripted_app"] = True

                facebook_pages.append(data)

        fb_user = {
            "facebook_first_name": r_json["first_name"],
            "facebook_user_id": facebook_user_id,
            "facebook_pages": facebook_pages
        }
        return fb_user

    def connect_facebook_user(self, access_token):
        # generar token de la aplicación
        params = {
            "client_id": app.config["FB_APP_ID"],
            "client_secret": app.config["FB_APP_SECRET"],
            "grant_type": "client_credentials"
        }
        url = "https://graph.facebook.com/v2.11/oauth/access_token"
        r = requests.get(url, params=params)
        r_json = r.json()
        econnect_logger.error(r_json)
        app_token = r_json["access_token"]
        # inspeccionar token
        url = "https://graph.facebook.com/debug_token?input_token={}&access_token={}".format(access_token, app_token)
        r = requests.get(url)
        r_json = r.json()
        econnect_logger.error(r_json)
        token_user_id = r_json["data"]["user_id"]
        token_scopes = r_json["data"]["scopes"]
        token_app_id = r_json["data"]["app_id"]

        if token_app_id != app.config["FB_APP_ID"]:
            return

        # Save user token
        db = get_db()
        query = {"uuid": self.user_id}
        user = db["db_users"]["users"].find_one(query)
        update = {
            "$set": {
                "facebook_user": {
                    "facebook_user_id": token_user_id,
                    "facebook_access_token": access_token
                }
            }
        }
        db["db_users"]["users"].update_one(query, update)


@login_manager.user_loader
def load_user(user_id):
    return user_class("", int(user_id))


@main.route('/', methods=['GET'])
@login_required
def index():
    fuser = current_user.get_facebook_user()
    url_fbauth = "/facebook_auth_a"
    return render_template('index.html', fuser=fuser, url_fbauth=url_fbauth)


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    username = request.form.get('username')
    password = request.form.get('password')
    if username is not None:
        # Login and validate the user.
        # user should be an instance of your `User` class
        user = user_class(username)
        user.check_autentication(username, password)
        login_user(user)

        flash('Logged in successfully.')

        next = request.args.get('next')
        # is_safe_url should check if the url is safe for redirects.
        # See http://flask.pocoo.org/snippets/62/ for an example.
        if not is_safe_url(next):
            return abort(400)

        return redirect(next or url_for('.index'))
    return render_template('login.html', username=username)


@main.route('/action_to_page/<page_id>/<action>', methods=['GET'])
@login_required
def subscribe_to_page(page_id, action):
    if action not in ["subscribe", "unsubscribe"]:
        abort(500)
    db = get_db()
    query = {"uuid": current_user.user_id}
    user = db["db_users"]["users"].find_one(query)
    if user["facebook_user"] is None:
        return None
    facebook_access_token = user["facebook_user"]["facebook_access_token"]
    facebook_user_id = user["facebook_user"]["facebook_user_id"]

    params = {
        "access_token": facebook_access_token
    }
    url = "https://graph.facebook.com/v2.11/me?fields=accounts"
    r = requests.get(url, params=params)
    r_json = r.json()
    if "error" in r_json:
        return None
    print(r.text)
    page_access_token = None
    for facebook_page in r_json["accounts"]["data"]:
        if facebook_page["id"] == page_id:
            page_access_token = facebook_page["access_token"]

    if page_access_token is None:
        abort(500)

    params = {
        "access_token": page_access_token
    }
    url = "https://graph.facebook.com/v2.11/{}/subscribed_apps".format(page_id)
    if action == "subscribe":
        r = requests.post(url, params=params)
    elif action == "unsubscribe":
        r = requests.delete(url, params=params)
    else:
        abort(500)
    return redirect(url_for('mybots'))


@main.route('/facebook_auth_a', methods=['GET'])
@login_required
def auth_a():
    params = {
        "client_id": app.config["FB_APP_ID"],
        "redirect_uri": "https%3A%2F%2Fconnect.eibriel.com%2Ffacebook_auth_b",
        "state": current_user.get_facebook_auth_state(True),
        "scope": "pages_messaging,read_page_mailboxes,manage_pages,publish_pages,instagram_basic,instagram_manage_comments"
    }
    url_fbauth = "https://www.facebook.com/v2.11/dialog/oauth?client_id={}&redirect_uri={}&state={}&scope={}"
    url_fbauth = url_fbauth.format(params["client_id"], params["redirect_uri"], params["state"], params["scope"])
    return redirect(url_fbauth)


@main.route('/facebook_auth_b', methods=['GET'])
@login_required
def auth_b():
    code = request.args.get('code')
    state = request.args.get('state')
    if state != current_user.get_facebook_auth_state():
        abort(500)

    # intercambiar por token de acceso
    params = {
        "client_id": app.config["FB_APP_ID"],
        "redirect_uri": "https://connect.eibriel.com/facebook_auth_b",
        "client_secret": app.config["FB_APP_SECRET"],
        "code": code
    }
    url = "https://graph.facebook.com/v2.11/oauth/access_token"
    r = requests.get(url, params=params)
    r_json = r.json()
    econnect_logger.error(r_json)
    access_token = r_json["access_token"]
    token_type = r_json["token_type"]
    # expires_in = r_json["expires_in"]
    current_user.connect_facebook_user(access_token)
    if 0:
        try:
            tokens = db["db_users"][""][db_id]
            create_tokens = False
        except KeyError:
            tokens = {'_id': db_id, "users_tokens": {}, "pages_tokens": {}}
            create_tokens = True
        tokens["users_tokens"][app.config["FB_ADMIN_ID"]] = access_token

        # Get page token
        params = {
            "access_token": access_token
        }
        url = "https://graph.facebook.com/me/accounts"
        r = requests.get(url, params=params)
        r_json = r.json()
        econnect_logger.error(r_json)
        page_token = ""
        for page in r_json["data"]:
            if page["id"] == app.config["FB_PAGE_ID"]:
                page_token = page["access_token"]

        tokens["pages_tokens"][app.config["FB_PAGE_ID"]] = page_token

        if create_tokens:
            db.create_document(tokens)
        else:
            tokens.save()
    return redirect(url_for('.index'))


@app.route("/mybots")
@login_required
def mybots():
    bots = current_user.get_bots()
    fuser = current_user.get_facebook_user()
    return render_template('mybots.html', bots=bots, fuser=fuser)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@main.route('/api/facebook', methods=['GET', 'POST'])
def facebook():
    # facebook_logger.error(request)
    econnect_logger.error(request.json)
    config = app.config
    # Facebook Challenge
    if request.method == 'GET':
        hub_mode = request.args.get('hub.mode', '')
        hub_verify_token = request.args.get('hub.verify_token', '')
        hub_challenge = request.args.get('hub.challenge', '')
        if hub_mode == 'subscribe' and hub_verify_token == config["FB_HUB_VERIFY_TOKEN"]:
            return hub_challenge
        else:
            abort(403)
    elif request.method == 'POST':
        msg = request.json
        if "object" in msg and msg['object'] == 'page':
            for entry in msg['entry']:
                if "messaging" in entry:
                    process_facebook_input(entry)
                elif "changes" in entry:
                    process_facebook_feed(entry)
        elif "object" in msg and msg['object'] == 'instagram':
            for entry in msg['entry']:
                if "changes" in entry:
                    process_instagram_comment(entry)
    return jsonify({})
