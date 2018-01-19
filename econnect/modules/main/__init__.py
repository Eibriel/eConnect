import logging

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

    def get_facebook_user(self):
        return None


@login_manager.user_loader
def load_user(user_id):
    return user_class("", int(user_id))


@main.route('/', methods=['GET'])
@login_required
def index():
    fuser = current_user.get_facebook_user()

    params = {
        "client_id": app.config["FB_APP_ID"],
        "redirect_uri": "https%3A%2F%2Feibrielbot.mybluemix.net%2Ffacebook_auth_b",
        "state": "123",
        "scope": "pages_messaging,read_page_mailboxes,manage_pages,publish_pages,instagram_basic,instagram_manage_comments"
    }
    url_fbauth = "https://www.facebook.com/v2.11/dialog/oauth?client_id={}&redirect_uri={}&state={}&scope={}"
    url_fbauth = url_fbauth.format(params["client_id"], params["redirect_uri"], params["state"], params["scope"])

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

        return redirect(next or url_for('main.index'))
    return render_template('login.html', username=username)


@app.route("/mybots")
@login_required
def settings():
    bots = current_user.get_bots()
    return render_template('mybots.html', bots=bots)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
