from flask import Flask, redirect, url_for, session, request, jsonify,render_template
from authlib.integrations.flask_client import OAuth
import logging
import os
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_secret_key')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'

# OAuth setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    server_metadata_url=CONF_URL,
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# @app.route('/')
# def homepage():
#     user = session.get('user')
#     return render_template('home.html', user=user)

@app.route('/')
def index():
    user = session.get('google_token')
    if user:
        return f"""
            <h2>Welcome abc</h2>
            <p>Email: def </p>
            <img src="abc" width="100"><br>
            <a href="/logout">Logout</a>
        """
    return '<a href="/login">Login with Google</a>'

@app.route('/login')
def login():
    redirect_uri = url_for('authorized', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorized():
    logging.info("I am inside Authorized_code")
    logging.debug(oauth)
    response = google.authorize_access_token()
    if response is None or response.get('access_token') is None:
        logger.warning('Access denied or no access token provided.')
        return 'Access denied: reason={} error={}'.format(
            request.args['error'],
            request.args['error_description']
        )
    session['google_token'] = (response['access_token'], '')
    me = response.get('userinfo')
    logger.info(f"User authorized: {me['email']}")
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


# def get_google_oauth_token():
#     return session.get('google_token')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)