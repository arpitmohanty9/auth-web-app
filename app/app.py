from flask import Flask, flash, redirect, url_for, session, request, jsonify,render_template
from authlib.integrations.flask_client import OAuth
import logging
import os
import secrets # For generating secure random strings
from dotenv import load_dotenv
load_dotenv()
from flask_cors import CORS # Import Flask-CORS


from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super_secret_fallback_key")
app.config['SESSION_COOKIE_NAME'] = 'google-oauth-session' # Optional: name your session cookie

# Initialize Flask-CORS
# For development, allowing all origins is fine.
# For production, replace "*" with your specific frontend domain, e.g., "https://your-app.com"
# You can also apply CORS to specific routes if needed.
CORS(app)

#set a timput for flask session object
app.permanent_session_lifetime = timedelta(minutes=5)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'

# OAuth setup
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'}, # Request user's email and profile info
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs', # Required for ID token verification
)

# @app.route('/')
# def homepage():
#     user = session.get('user')
#     return render_template('home.html', user=user)

# @app.route('/')
# def index():
#     if 'google_token' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to index or dashboard
    if session.get('user'):
        logger.info(f'User : {session.get('user').get('name')} is already logged in')
        return redirect(url_for('dashboard'))

    # Handle traditional form submission (from previous HTML)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Replace with your actual database authentication logic
        if username == 'testuser' and password == 'testpass':
            session['user'] = {'email': username, 'name': 'Test User'}
            flash('Traditional login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    # Pass the Google Client ID to the HTML template for the JS part
    # This is safe as the client ID is public. The secret is kept server-side.
    google_client_id = os.environ.get("GOOGLE_CLIENT_ID")
    return render_template('login.html', google_client_id=google_client_id)

@app.route('/login/google')
def login_google():
    """Initiates the Google OAuth login flow."""
    # This route is called when the "Sign in with Google" button is clicked
    # (or when the JS in the HTML page triggers the Google One Tap/popup)
    # Authlib will automatically handle the redirect to Google's authorization URL.
    # Generate a secure random nonce
    nonce = secrets.token_urlsafe(32)
    session['oauth_nonce'] = nonce # Store nonce in session for later verification

    redirect_uri = url_for('authorize_google', _external=True)
    # Pass the nonce as an extra parameter to Google
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/auth/google/callback')
def authorize_google():
    """Handles the callback from Google after successful authentication."""
    try:
        # Exchange the authorization code for an access token and ID token
        token = oauth.google.authorize_access_token()
        # The 'token' dictionary contains 'access_token', 'id_token', 'expires_in', etc.

        # Verify the ID token and get user info
        # Authlib automatically verifies the ID token if jwks_uri is configured
        user_info = oauth.google.parse_id_token(token,session['oauth_nonce'])
        
        # Clear the nonce from the session after successful verification
        session.pop('oauth_nonce', None)
        # Store user information in the session
        session['user'] = {
            'id': user_info.get('sub'), # Google user ID
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'picture': user_info.get('picture')
        }
        flash('Successfully signed in with Google!', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        flash(f'Google login failed: {e}', 'error')
        print(f"Google OAuth Error: {e}")
        return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    user = session.get('user')
    if not user:
        flash('Please log in to access the dashboard.', 'info')
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=user) # You'd create a dashboard.html

@app.route('/logout')
def logout():
    session.pop('user', None) # Remove user from session
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)