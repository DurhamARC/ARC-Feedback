from flask import Flask, redirect, render_template, request, jsonify, current_app, flash, url_for, session, abort
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import xml.etree.ElementTree as ET
from dotenv import load_dotenv
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import pandas as pd
import requests
import re
from flask_caching import Cache
import os


load_dotenv()
db = SQLAlchemy()
utc_now = datetime.now(timezone.utc)
uk_time = utc_now.astimezone(ZoneInfo("Europe/London"))

class Record(db.Model):
    __tablename__ = 'records'
    id = db.Column(db.Integer, primary_key=True)
    orcid = db.Column(db.String(19), db.ForeignKey('users.orcid'), nullable=False, index=True)
    title = db.Column(db.String(500), nullable=False, index=True)
    type = db.Column(db.Enum('publication', 'funding', name='record_type'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=uk_time, nullable=False, index=True)

    __table_args__ = (
        db.Index('idx_record_orcid_type', 'orcid', 'type'),
    )

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    orcid = db.Column(db.String(19), nullable=False, unique=True, index=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=uk_time, nullable=False, index=True)

    records = db.relationship('Record', backref='users', lazy=True)

    __table_args__ = (
        db.Index('idx_user_orcid_name', 'orcid', 'name'),
    )

def init_db(app):
    def wrapper():
        with app.app_context():
            db.create_all()
    return wrapper

class BaseFlaskApp:
    def __init__(self, app_name):
        self.app = Flask(app_name)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        db.init_app(self.app)
        self._register_cli_commands()

    def _register_cli_commands(self):
        @self.app.cli.command("init-db")
        def init_db_command():
            """Initialize the database."""
            with self.app.app_context():
                db.create_all()
            print("Database initialized")

    def run(self, *args, **kwargs):
        self.app.run(*args, **kwargs)


def handle_errors(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"API request failed: {str(e)}")
            flash("Service temporarily unavailable. Please try again later.", "error")
            return redirect(url_for('home'))
        except Exception as e:
            current_app.logger.error(f"Unexpected error in {f.__name__}: {str(e)}")
            flash("An unexpected error occurred. Please try again.", "error")
            return redirect(url_for('home'))
    return wrapper

class OrcidApp(BaseFlaskApp):
    def __init__(self, app_name):
        super().__init__(app_name)
        
        self.app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY')
        self.app.config['WTF_CSRF_TIME_LIMIT'] = 3600
        self.csrf = CSRFProtect(self.app)
        

        self._limiter = Limiter(
            get_remote_address,
            app=self.app,
            default_limits=["200 per day", "50 per hour"],
            storage_uri="memory://",
        )

        logging.basicConfig(level=logging.INFO)
        self.app.logger.handlers.clear()
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.app.logger.addHandler(handler)

        self.app.config['CACHE_TYPE'] = 'SimpleCache'
        self.app.config['CACHE_DEFAULT_TIMEOUT'] = 3600  # 1 hour cache
        self._cache = Cache(self.app)
        self.app.secret_key = os.getenv("APP_SECRET_KEY")

        # Register routes after all components are initialized
        self._register_routes()

    def _register_routes(self):
        self.app.route("/")(self.home)
        self.app.route("/publications/search")(self.orcid_works_search)
        self.app.route("/fundings/search")(self.orcid_fundings_search)
        self.app.route('/publications', methods=['GET', 'POST'])(self.get_orcid_works_data)
        self.app.route('/fundings', methods=['GET', 'POST'])(self.get_orcid_fundings_data)
        self.app.route('/api/token', methods=['GET', 'POST'])(self.get_access_token)
        self.app.route('/process/publications', methods=['POST'])(self.process_works_form)
        self.app.route('/process/fundings', methods=['POST'])(self.process_fundings_form)
        self.app.route('/auth/orcid')(self.initiate_orcid_auth)
        self.app.route('/auth/orcid/callback')(self.handle_orcid_callback)

    @handle_errors
    def home(self):
        try:
            return render_template("home.html")
        except Exception as e:
            current_app.logger.error(f"Template rendering failed: {str(e)}")
            abort(500)

    @handle_errors
    def orcid_works_search(self):
        try:
            return render_template("orcid_id_works.html")
        except Exception as e:
            current_app.logger.error(f"Template rendering failed: {str(e)}")
            abort(500)

    @handle_errors
    def orcid_fundings_search(self):
        try:
            return render_template("orcid_id_fundings.html")
        except Exception as e:
            current_app.logger.error(f"Template rendering failed: {str(e)}")
            abort(500)

    def _fetch_orcid_token(self):
        @self._cache.memoize(timeout=3500)
        def _inner_fetch():
            """Fetches ORCiD access token using client credentials."""
            url = "https://orcid.org/oauth/token"
            headers = {"Accept": "application/json"}
            data = {
                "client_id": os.getenv("ORCID_CLIENT_ID"),
                "client_secret": os.getenv("ORCID_CLIENT_SECRET"),
                "grant_type": "client_credentials",
                "scope": "/read-public"
            }
            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 200:
                current_app.logger.info('Token fetch successful')
                return response.json().get("access_token")
            else:
                current_app.logger.info(f"Token fetch failed: {response.status_code} - {response.text}")
                return None
        return _inner_fetch()
    
    @handle_errors
    def get_access_token(self):
        """Route handler for /api/token (returns JSON token)."""
        try:
            token = self._fetch_orcid_token()
            if token:
                return jsonify({"access_token": token})
            else:
                current_app.logger.error("Failed to fetch ORCID token")
                return jsonify({
                    "error": "Failed to fetch token",
                    "details": "Check server logs for more information"
                }), 500
        except Exception as e:
            current_app.logger.error(f"Token endpoint error: {str(e)}")
            return jsonify({
                "error": "Internal server error",
                "details": str(e)
            }), 500
        
    def _validate_orcid_id(self, orcid_id):
            """Validates ORCiD format"""
            pattern = r'^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$'
            return re.match(pattern, orcid_id.strip()) is not None
            
    @handle_errors
    def get_orcid_works_data(self):
        self._limiter.limit("10 per minute")(lambda: None)  # Apply rate limit
        access_token = self._fetch_orcid_token()
        if not access_token:
            return jsonify({"error": "Token failure"}), 500
        
        if request.method == 'POST':
            # Check for authenticated session first
            if 'orcid_id' in session:
                orcid_id = session['orcid_id']
            else:
                orcid_id = request.form.get('orcidInput')
                if not self._validate_orcid_id(orcid_id):
                    flash("Invalid ORCiD. Use the XXXX-XXXX-XXXX-XXXX format.")
                    return redirect(request.referrer)
            
            cache_key = f"orcid_works_{orcid_id}"
            cached_data = self._cache.get(cache_key)
            if cached_data:
                return render_template('works_results.html',
                                    unique_titles=cached_data,
                                    orcidInput=orcid_id)
                
            url = f'https://pub.orcid.org/v3.0/{orcid_id}/works'
        else:
            url = 'https://pub.orcid.org/v3.0/{ORCID_ID}/works'

        headers = {
            'Content-type': 'application/vnd.orcid+xml',
            'Authorization': f'Bearer {access_token}'  # Use dynamic token
        }

        response = requests.get(url, headers=headers)

        # status code 200
        if response.status_code == 200:
            # Debugging purpose
            if self.app.debug:
                file_path = 'works_response_data.xml'
                with open(file_path, 'w') as file:
                    file.write(response.text)

            # Define XML namespaces
            namespaces = {
            'activities': 'http://www.orcid.org/ns/activities',
            'common': 'http://www.orcid.org/ns/common',
            'work': 'http://www.orcid.org/ns/work',
            }

            root = ET.fromstring(response.text)

            # Extract the titles
            titles = [title.text for title in root.findall('.//common:title', namespaces)]

            # filter titles and insert them into a list
            unique_titles = list(set(titles))

            # Pass the titles to the template
            self._cache.set(cache_key, unique_titles, timeout=120)  # Cache for 2 minutes / 1 day in production
            return render_template('works_results.html',
                                unique_titles=unique_titles,
                                orcidInput=orcid_id)
        else:
            # Error message if the request is not successful
            current_app.logger.info(f'Error: {response.status_code} - {response.text}')
            # Return an error response in JSON format
            return jsonify({"error": f"{response.status_code} - {response.text}"}), response.status_code
            pass

    @handle_errors
    def get_orcid_fundings_data(self):
        self._limiter.limit("10 per minute")(lambda: None)  # Apply rate limit
        access_token = self._fetch_orcid_token()
        if not access_token:
            return jsonify({"error": "Token failure"}), 500

        if request.method == 'POST':
            orcid_id = request.form.get('orcidInput')
            if not self._validate_orcid_id(orcid_id):
                flash("Invalid ORCiD. Use the XXXX-XXXX-XXXX-XXXX format.")
                return redirect(request.referrer)
            
            cache_key = f"orcid_fundings_{orcid_id}"
            cached_data = self._cache.get(cache_key)
            if cached_data:
                return render_template('fundings_results.html',
                                    titles=cached_data)
                
            url = f'https://pub.orcid.org/v3.0/{orcid_id}/fundings'
        else:
            url = 'https://pub.orcid.org/v3.0/{ORCID_ID}/fundings'

        headers = {
            'Content-type': 'application/vnd.orcid+xml',
            'Authorization': f'Bearer {access_token}'  # Dynamic token
        }

        # Make the GET request
        response = requests.get(url, headers=headers)

        if response.status_code == 200:

            # Debugging purpose
            if self.app.debug:
                file_path = 'fundings_response_data.xml'
                with open(file_path, 'w') as file:
                    file.write(response.text)

            namespaces = {
                'activities': 'http://www.orcid.org/ns/activities',
                'common': 'http://www.orcid.org/ns/common',
                'work': 'http://www.orcid.org/ns/work',
            }

            root = ET.fromstring(response.text)

            # Extract titles
            titles = [title.text for title in root.findall('.//common:title', namespaces)]

            # Return the same template
            self._cache.set(cache_key, titles, timeout=120)  # Cache for 2 minutes
            return render_template('fundings_results.html',
                                titles=titles)
        else:
            # Handle errors
            current_app.logger.info(f'Error: {response.status_code} - {response.text}')
            return jsonify({"error": f"{response.status_code} - {response.text}"}), response.status_code



    def process_works_form(self):

        selected_titles = request.form.getlist('selected_titles')
        username = request.form.get('username')
        orcid_input = request.form.get("orcidInput")

        current_app.logger.info(request.form)

        if not re.match(r'^[A-Za-z ]{2,50}$', username):
            flash('Invalid name format', 'error')
            return redirect(url_for('orcid_works_search'))

        try:
            with self.app.app_context():
                for title in selected_titles:
                    users = User.query.filter_by(orcid=orcid_input).first()
                    if not users:
                        users = User(
                            orcid=orcid_input,
                            name=username
                        )
                        db.session.add(users)
                        db.session.commit()
                    
                    record = Record(
                        title=title,
                        type='publication',
                        orcid=orcid_input,
                        users=users
                    )
                    
                    db.session.add(record)

                db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Database error: {str(e)}")

        return redirect('/')




    @handle_errors
    def initiate_orcid_auth(self):
        """Initiate ORCiD OAuth flow"""
        # Generate random state parameter for CSRF protection
        import secrets
        state = secrets.token_urlsafe(16)
        session['oauth_state'] = state
        
        # Build authorization URL
        auth_url = (
            "https://orcid.org/oauth/authorize?"
            f"client_id={os.getenv('ORCID_CLIENT_ID')}&"
            "response_type=code&"
            "scope=/authenticate&"
            f"redirect_uri={os.getenv('ORCID_REDIRECT_URI')}&"
            f"state={state}"
        )
        return redirect(auth_url)

    @handle_errors
    def handle_orcid_callback(self):
        """Handle ORCiD OAuth callback"""
        # Verify state parameter
        if session.get('oauth_state') != request.args.get('state'):
            current_app.logger.error("Invalid state parameter in OAuth callback")
            abort(401)
        
        code = request.args.get('code')
        if not code:
            current_app.logger.error("Missing authorization code in callback")
            abort(400)
            
        token_url = "https://orcid.org/oauth/token"
        headers = {"Accept": "application/json"}
        data = {
            "client_id": os.getenv("ORCID_CLIENT_ID"),
            "client_secret": os.getenv("ORCID_CLIENT_SECRET"),
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": os.getenv("ORCID_REDIRECT_URI")
        }
        
        response = requests.post(token_url, headers=headers, data=data)
        if response.status_code != 200:
            current_app.logger.error(f"Token exchange failed: {response.text}")
            abort(500)
            
        token_data = response.json()
        access_token = token_data.get("access_token")
        orcid_id = token_data.get("orcid")
        
        if not access_token or not orcid_id:
            current_app.logger.error("Missing access token or ORCID in response")
            abort(500)
            
        # Store user info in session
        session['orcid_id'] = orcid_id
        session['access_token'] = access_token
        
        # Redirect to publications page
        return redirect(url_for('orcid_works_search'))

    def process_fundings_form(self):
        selected_titles = request.form.getlist('selected_titles')
        username = request.form.get('username')
        orcid_input = request.form.get('orcidInput')

        if not re.match(r'^[A-Za-z ]{2,50}$', username):
            flash('Invalid name format', 'error')
            return redirect(url_for('orcid_fundings_search'))

        try:
            with self.app.app_context():
                for title in selected_titles:
                    users = User.query.filter_by(orcid=orcid_input).first()
                    if not users:
                        users = User(
                            orcid=orcid_input,
                            name=username
                        )
                        db.session.add(users)
                        db.session.commit()
                    
                    record = Record(
                        title=title,
                        type='funding',
                        orcid=orcid_input,
                        users=users
                    )
                    
                    db.session.add(record)

                db.session.commit()
                flash('Fundings saved successfully', 'success')
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Database error: {str(e)}")
            flash('Error saving fundings', 'error')
        
        return redirect('/')
    

orcid_app = OrcidApp(__name__)

if __name__ == "__main__":
    orcid_app.run(host="0.0.0.0", port=5000)
