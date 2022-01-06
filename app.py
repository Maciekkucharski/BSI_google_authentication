import os
import pathlib

import google.auth.transport.requests
import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol

app = Flask("Google Login App BSI")
app.secret_key = "ENgzHdBt2rG9scOdaizR"

# Workaround for using this app locally(there is a rule that address need to be https and that is a bypass)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "488226868290-c67qmfmhs9c9beds2skcjmdn07m5b2nr.apps.googleusercontent.com"
# path to out client secret file, in that case we are taking parent path and joining it with the name of the file
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

# Flow is holding information on how do we want to authorize our users
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


# function protecting content
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


# basic site that everybody sees with simple html login button
@app.route("/")
def index():
    return "Hello World <a href='/login'><button>Login</button></a>"


@app.route("/login")
def login():
    # saving the state in order to validate it later
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


# redirects us here after in order to authorize credentials
@app.route("/callback")
def callback():
    # obtaining an access token to api
    flow.fetch_token(authorization_response=request.url)
    # verifying the state
    if not session["state"] == request.args["state"]:
        abort(500)
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    # verifying data we received
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get('email')
    return redirect("/content")


# Our goal page after logging in correctly, with logout possibility
@app.route("/content")
@login_is_required
def content_area():
    return f"{type(session)}Hello {session['name']}! Your email is {session['email']} <br/> <a href='/logout'><button>Logout</button></a>"


# address to clear your session and log out
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)
