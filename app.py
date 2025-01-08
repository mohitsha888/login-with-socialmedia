from flask import Flask, redirect, request, url_for, session, render_template
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import os
from dotenv import load_dotenv
import requests


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

CLIENT_SECRETS_FILE = "client_data.json"
SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email'
]

flow = Flow.from_client_secrets_file(
    CLIENT_SECRETS_FILE,
    scopes=SCOPES,
    redirect_uri="http://localhost:5000/callback"
)

@app.route("/")
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    session.clear()
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    if 'state' not in session:
        return redirect(url_for('index'))
    
    try:
        flow.fetch_token(authorization_response=request.url)

        if not session["state"] == request.args["state"]:
            return redirect(url_for('index'))

        credentials = flow.credentials
        request_session = requests.session()
        token_request = google_requests.Request(session=request_session)

        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=os.getenv('GOOGLE_CLIENT_ID')
        )

        session["google_id"] = id_info.get("sub")
        session["name"] = id_info.get("name")
        session["email"] = id_info.get("email")
        return redirect(url_for("protected_area"))
    except Exception as e:
        print(f"Error in callback: {e}")
        return redirect(url_for('index'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/protected_area")
def protected_area():
    if "google_id" not in session:
        return redirect(url_for("index"))
    return render_template('protected.html', name=session['name'], email=session['email'])

if __name__ == "__main__":
    app.run(debug=True)