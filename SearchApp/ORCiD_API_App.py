from flask import Flask, redirect, render_template, request, jsonify, current_app, flash, url_for, session, abort, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, DateField
from wtforms.validators import DataRequired, Length
from datetime import datetime, timezone, timedelta
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
import xml.etree.ElementTree as ET
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_caching import Cache
from flask_wtf import FlaskForm
from dotenv import load_dotenv
from zoneinfo import ZoneInfo
from functools import wraps
from io import BytesIO
import pandas as pd
import requests
import logging
import click
import re
import os
import secrets

load_dotenv()
db = SQLAlchemy()
utc_now = datetime.now(timezone.utc)
uk_time = utc_now.astimezone(ZoneInfo("Europe/London"))

def normalise_title(title):
    if not title or not isinstance(title, str):
        return ""
    
    normalised = title.lower()
    normalised = re.sub(r'^(the|a|an)\s+', '', normalised)
    normalised = re.sub(r'[^\w\s]', '', normalised)
    normalised = re.sub(r'\s+', ' ', normalised).strip()
    normalised = re.sub(r'&[a-zA-Z0-9#]+;', '', normalised)
    normalised = normalised.encode('ascii', 'ignore').decode('ascii')
    return normalised

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

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')

class DateRangeForm(FlaskForm):
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Download')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

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

        @self.app.cli.command("create-admin")
        @click.argument("username")
        @click.argument("password")
        def create_admin(username, password):
            """Create an admin user."""
            with self.app.app_context():
                admin = Admin(username=username)
                admin.set_password(password)
                db.session.add(admin)
                db.session.commit()
            print(f"Admin user {username} created.")

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
        self.app.config['WTF_CSRF_TIME_LIMIT'] = 900
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
        self.app.config['CACHE_DEFAULT_TIMEOUT'] = 900
        self.app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
        self._cache = Cache(self.app)
        
        self.app.secret_key = os.getenv("APP_SECRET_KEY")
        self.migrate = Migrate(self.app, db)
        self._register_routes()
        self.app.config.update(
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_SAMESITE='Lax'
        )
        
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
        self.app.route('/admin/login', methods=['GET', 'POST'])(self.admin_login)
        self.app.route('/admin/logout')(self.admin_logout)
        self.app.route('/admin/dashboard')(self.admin_dashboard)
        self.app.route('/admin/download/all')(self.download_all)
        self.app.route('/admin/download/time_range', methods=['GET', 'POST'])(self.download_time_range)
        self.app.route('/admin/clear_database', methods=['GET', 'POST'])(self.clear_database)
        self.app.route('/admin/data')(self.admin_data)

    @handle_errors
    def home(self):
        return render_template("home.html")

    @handle_errors
    def orcid_works_search(self):
        return render_template("orcid_id_works.html", enable_orcid_login=os.getenv('ENABLE_ORCID_LOGIN', 'true').lower() in ('true'), debug_mode=current_app.debug)

    @handle_errors
    def orcid_fundings_search(self):
        return render_template("orcid_id_fundings.html", debug_mode=current_app.debug)

    def _fetch_orcid_token(self):
        @self._cache.memoize(timeout=3500)
        def _inner_fetch():
            url = "https://orcid.org/oauth/token"
            headers = {"Accept": "application/json"}
            data = {
                "client_id": os.getenv("ORCID_CLIENT_ID"),
                "client_secret": os.getenv("ORCID_CLIENT_SECRET"),
                "grant_type": "client_credentials",
                "scope": "/read-public"
            }
            try:
                response = requests.post(url, headers=headers, data=data, timeout=10)
                response.raise_for_status()
                return response.json().get("access_token")
            except requests.exceptions.RequestException as e:
                return None
        return _inner_fetch()

    @handle_errors
    def get_access_token(self):
        token = self._fetch_orcid_token()
        if token:
            return jsonify({"access_token": token})
        else:
            return jsonify({"error": "Failed to fetch token", "details": "Check server logs"}), 500

    def _validate_orcid_id(self, orcid_id):
        pattern = r'^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$'
        return re.match(pattern, orcid_id.strip()) is not None

    @handle_errors
    def get_orcid_works_data(self):
        self._limiter.limit("10 per minute")(lambda: None)

        orcid_id = None
        source = None

        if request.method == 'GET':
            if 'orcid_id' in session:
                orcid_id = session['orcid_id']
                source = 'session'
            else:
                flash("Please log in with ORCID or enter your ORCID ID on the search page.", "info")
                return redirect(url_for('orcid_works_search'))

        elif request.method == 'POST':
            orcid_id = request.form.get('orcidInput')
            source = 'form'
            if not self._validate_orcid_id(orcid_id):
                flash("Invalid ORCiD format submitted. Use XXXX-XXXX-XXXX-XXXX.", "error")
                return redirect(url_for('orcid_works_search'))
        else:
            abort(405)

        access_token = self._fetch_orcid_token()
        if not access_token:
            flash("Could not authenticate with the ORCID service at this time. Please try again later.", "error")
            return redirect(url_for('orcid_works_search'))

        cache_key = f"orcid_works_{orcid_id}"
        cached_data = self._cache.get(cache_key)
        if cached_data:
            username = cached_data.get('name', '')
            return render_template('works_results.html',
                                   unique_titles=cached_data.get('titles', []),
                                   username=username,
                                   orcidInput=orcid_id)
        
        url = f'https://pub.orcid.org/v3.0/{orcid_id}/works'
        headers = {
            'Accept': 'application/vnd.orcid+xml',
            'Authorization': f'Bearer {access_token}'
        }

        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()

            namespaces = {
                'common': 'http://www.orcid.org/ns/common',
                'work': 'http://www.orcid.org/ns/work',
            }

            root = ET.fromstring(response.text)

            titles = [title.text for title in root.findall('.//work:title/common:title', namespaces) if title.text]
            if not titles:
                 flash(f"No publications found for ORCID {orcid_id}.", "info")

            all_source_names = [name.text for name in root.findall('.//common:source-name', namespaces) if name.text]
            name = ''
            if all_source_names:
                from collections import Counter
                name_counts = Counter(all_source_names)
                threshold = len(all_source_names) * 0.9
                common_names = [name for name, count in name_counts.items() if count >= threshold]
                name = common_names[0] if common_names else all_source_names[0]
            else:
                 if 'user_name' in session:
                     name = session['user_name']

            normalised_titles = {normalise_title(title): title for title in titles if title}
            unique_titles = list(normalised_titles.values())

            cache_data = {'titles': unique_titles, 'name': name}
            self._cache.set(cache_key, cache_data, timeout=120)

            return render_template('works_results.html',
                                   unique_titles=unique_titles,
                                   username=name,
                                   orcidInput=orcid_id)

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 404:
                flash(f"Could not find an ORCID record matching {orcid_id}. Please check the ID.", "error")
            elif status_code == 401 or status_code == 403:
                 flash("Authorization error with ORCID. Please check credentials or contact support.", "error")
                 self._cache.delete_memoized(self._fetch_orcid_token)
            else:
                flash(f"Error fetching data from ORCID (Code: {status_code}). Please try again later.", "error")
            return redirect(url_for('orcid_works_search'))
        except requests.exceptions.RequestException as e:
            flash("Could not connect to the ORCID service. Please check your network or try again later.", "error")
            return redirect(url_for('orcid_works_search'))
        except ET.ParseError as e:
            flash("Received invalid data format from ORCID. Please try again.", "error")
            return redirect(url_for('orcid_works_search'))
        except Exception as e:
            flash("An unexpected error occurred while processing your publications.", "error")
            return redirect(url_for('orcid_works_search'))

    @handle_errors
    def get_orcid_fundings_data(self):
        self._limiter.limit("10 per minute")(lambda: None)
        access_token = self._fetch_orcid_token()
        if not access_token:
            flash("Could not authenticate with the ORCID service.", "error")
            return redirect(url_for('orcid_fundings_search'))

        orcid_id = None
        if request.method == 'POST':
            orcid_id = request.form.get('orcidInput')
            if not self._validate_orcid_id(orcid_id):
                flash("Invalid ORCiD format. Use XXXX-XXXX-XXXX-XXXX.", "error")
                return redirect(url_for('orcid_fundings_search'))
        else:
            flash("Please enter an ORCID ID on the search page.", "info")
            return redirect(url_for('orcid_fundings_search'))

        cache_key = f"orcid_fundings_{orcid_id}"
        cached_data = self._cache.get(cache_key)
        if cached_data:
            return render_template('fundings_results.html', unique_titles=cached_data, orcidInput=orcid_id)

        url = f'https://pub.orcid.org/v3.0/{orcid_id}/fundings'
        headers = {
            'Accept': 'application/vnd.orcid+xml',
            'Authorization': f'Bearer {access_token}'
        }

        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()

            namespaces = {
                'common': 'http://www.orcid.org/ns/common',
                'funding': 'http://www.orcid.org/ns/funding'
            }

            root = ET.fromstring(response.text)
            titles = [title.text for title in root.findall('.//funding:title/common:title', namespaces) if title.text]
            if not titles:
                 flash(f"No funding found for ORCID {orcid_id}.", "info")

            normalised_titles = {normalise_title(title): title for title in titles if title}
            unique_titles = list(normalised_titles.values())

            self._cache.set(cache_key, unique_titles, timeout=120)

            return render_template('fundings_results.html', unique_titles=unique_titles, orcidInput=orcid_id)

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 404:
                flash(f"Could not find an ORCID record or fundings for {orcid_id}.", "error")
            elif status_code == 401 or status_code == 403:
                 flash("Authorization error with ORCID. Please check credentials or contact support.", "error")
                 self._cache.delete_memoized(self._fetch_orcid_token)
            else:
                flash(f"Error fetching funding data from ORCID (Code: {status_code}). Please try again later.", "error")
            return redirect(url_for('orcid_fundings_search'))
        except requests.exceptions.RequestException as e:
            flash("Could not connect to the ORCID service for fundings. Please check your network or try again later.", "error")
            return redirect(url_for('orcid_fundings_search'))
        except ET.ParseError as e:
            flash("Received invalid data format from ORCID for fundings. Please try again.", "error")
            return redirect(url_for('orcid_fundings_search'))
        except Exception as e:
            flash("An unexpected error occurred while processing your fundings.", "error")
            return redirect(url_for('orcid_fundings_search'))

    def process_works_form(self):
        selected_titles = request.form.getlist('selected_titles')
        username = request.form.get('username', '').strip()
        orcid_input = request.form.get("orcidInput")

        if not orcid_input or not self._validate_orcid_id(orcid_input):
             flash('Invalid or missing ORCID ID.', 'error')
             return redirect(url_for('orcid_works_search'))

        if username and not re.match(r"^[A-Za-zÀ-ÖØ-öø-ÿ.'\- ]{2,100}$", username):
             flash('Invalid characters in name or name too long/short.', 'error')
             return redirect(url_for('orcid_works_search'))

        if not selected_titles:
             flash('No publications selected to save.', 'warning')
             return redirect(url_for('orcid_works_search'))

        try:
            with self.app.app_context():
                user = User.query.filter_by(orcid=orcid_input).first()
                if not user:
                    user_name_to_save = username if username else "Name not provided"
                    user = User(orcid=orcid_input, name=user_name_to_save)
                    db.session.add(user)
                elif username and user.name != username:
                    user.name = username

                saved_count = 0
                for title in selected_titles:
                     existing_record = Record.query.filter_by(orcid=orcid_input, title=title, type='publication').first()
                     if not existing_record:
                         record = Record(title=title, type='publication', orcid=orcid_input, users=user)
                         db.session.add(record)
                         saved_count += 1

                if saved_count > 0:
                    db.session.commit()
                    flash(f'{saved_count} publication(s) saved successfully!', 'fireworks-success')
                else:
                    flash('No new publications were selected or saved.', 'info')

        except Exception as e:
            db.session.rollback()
            flash('An error occurred while saving the publications. Please try again.', 'error')
            return redirect(url_for('orcid_works_search'))

        return redirect(url_for('home'))

    @handle_errors
    def initiate_orcid_auth(self):
        state = secrets.token_urlsafe(16)
        session['oauth_state'] = state
        redirect_uri = os.getenv('ORCID_REDIRECT_URI')
        if not redirect_uri:
            flash("Application configuration error. Cannot initiate ORCID login.", "error")
            return redirect(url_for('home'))

        auth_url = (
            f"https://orcid.org/oauth/authorize?"
            f"client_id={os.getenv('ORCID_CLIENT_ID')}&"
            "response_type=code&"
            "scope=/authenticate&"
            f"redirect_uri={redirect_uri}&"
            f"state={state}"
        )
        return redirect(auth_url)

    @handle_errors
    def handle_orcid_callback(self):
        received_state = request.args.get('state')
        expected_state = session.pop('oauth_state', None)

        if not expected_state or received_state != expected_state:
            flash("Authentication session validation failed. Please try logging in again.", "error")
            abort(401)

        if 'error' in request.args:
            error = request.args.get('error')
            error_description = request.args.get('error_description', 'No description provided.')
            flash(f"ORCID login failed: {error_description}", "error")
            return redirect(url_for('orcid_works_search'))

        code = request.args.get('code')
        if not code:
            flash("Failed to receive authorization from ORCID. Please try again.", "error")
            abort(400)

        token_url = "https://orcid.org/oauth/token"
        headers = {"Accept": "application/json"}
        redirect_uri = os.getenv('ORCID_REDIRECT_URI')
        if not redirect_uri:
             flash("Application configuration error. Cannot complete ORCID login.", "error")
             abort(500)

        data = {
            "client_id": os.getenv("ORCID_CLIENT_ID"),
            "client_secret": os.getenv("ORCID_CLIENT_SECRET"),
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri
        }

        try:
            response = requests.post(token_url, headers=headers, data=data, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
             flash("Could not communicate with ORCID to finalize login. Please try again.", "error")
             abort(500)

        if response.status_code != 200:
            flash("Failed to finalize login with ORCID. Please try again.", "error")
            abort(500)

        try:
            token_data = response.json()
        except ValueError:
             flash("Received an invalid response from ORCID. Please try again.", "error")
             abort(500)

        orcid_id = token_data.get("orcid")
        user_name = token_data.get("name")

        if not orcid_id:
            flash("Failed to retrieve necessary credentials from ORCID. Please try again.", "error")
            abort(500)

        session['orcid_id'] = orcid_id
        if user_name:
             session['user_name'] = user_name
        session.permanent = True
        session.modified = True

        flash(f"Successfully logged in with ORCID {orcid_id}.", "success")
        return redirect(url_for('get_orcid_works_data'))

    def process_fundings_form(self):
        selected_titles = request.form.getlist('selected_titles')
        username = request.form.get('username', '').strip()
        orcid_input = request.form.get('orcidInput')

        if not orcid_input or not self._validate_orcid_id(orcid_input):
            flash('Invalid or missing ORCID ID.', 'error')
            return redirect(url_for('orcid_fundings_search'))

        if username and not re.match(r"^[A-Za-zÀ-ÖØ-öø-ÿ.'\- ]{2,100}$", username):
            flash('Invalid characters in name or name too long/short.', 'error')
            return redirect(url_for('orcid_fundings_search'))

        if not selected_titles:
            flash('No fundings selected to save.', 'warning')
            return redirect(url_for('orcid_fundings_search'))

        try:
            with self.app.app_context():
                user = User.query.filter_by(orcid=orcid_input).first()
                if not user:
                    user_name_to_save = username if username else "Name not provided"
                    user = User(orcid=orcid_input, name=user_name_to_save)
                    db.session.add(user)
                elif username and user.name != username:
                    user.name = username

                saved_count = 0
                for title in selected_titles:
                    existing_record = Record.query.filter_by(orcid=orcid_input, title=title, type='funding').first()
                    if not existing_record:
                        record = Record(title=title, type='funding', orcid=orcid_input, users=user)
                        db.session.add(record)
                        saved_count += 1

                if saved_count > 0:
                    db.session.commit()
                    flash(f'{saved_count} funding record(s) saved successfully!', 'success')
                else:
                    flash('No new funding records were selected or saved.', 'info')

        except Exception as e:
            db.session.rollback()
            flash('An error occurred while saving the funding records. Please try again.', 'error')
            return redirect(url_for('orcid_fundings_search'))

        return redirect(url_for('home'))

    def admin_login(self):
        form = AdminLoginForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            admin = Admin.query.filter_by(username=username).first()
            if admin and admin.check_password(password):
                session['admin_id'] = admin.id
                session.permanent = True
                flash('Login successful', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid username or password', 'error')
        return render_template('admin/login.html', form=form)

    def admin_logout(self):
        session.pop('admin_id', None)
        flash('You have been logged out', 'info')
        return redirect(url_for('admin_login'))

    @admin_required
    def admin_dashboard(self):
        return render_template('admin/dashboard.html')
    
    @admin_required
    def download_all(self):
        users = User.query.all()
        records = Record.query.all()
        users_data = [{'id': u.id, 'orcid': u.orcid, 'name': u.name, 'created_at': u.created_at} for u in users]
        records_data = [{'id': r.id, 'orcid': r.orcid, 'title': r.title, 'type': r.type, 'created_at': r.created_at} for r in records]
        df_users = pd.DataFrame(users_data)
        df_records = pd.DataFrame(records_data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df_users.to_excel(writer, sheet_name='Users', index=False)
            df_records.to_excel(writer, sheet_name='Records', index=False)
        output.seek(0)
        return send_file(output, download_name='all_data.xlsx', as_attachment=True)

    @admin_required
    def download_time_range(self):
        form = DateRangeForm()
        if form.validate_on_submit():
            start_date = form.start_date.data
            end_date = form.end_date.data
            records = Record.query.filter(Record.created_at.between(start_date, end_date)).all()
            users = User.query.filter(User.created_at.between(start_date, end_date)).all()
            users_data = [{'id': u.id, 'orcid': u.orcid, 'name': u.name, 'created_at': u.created_at} for u in users]
            records_data = [{'id': r.id, 'orcid': r.orcid, 'title': r.title, 'type': r.type, 'created_at': r.created_at} for r in records]
            df_users = pd.DataFrame(users_data)
            df_records = pd.DataFrame(records_data)
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                df_users.to_excel(writer, sheet_name='Users', index=False)
                df_records.to_excel(writer, sheet_name='Records', index=False)
            output.seek(0)
            return send_file(output, download_name=f'data_{start_date}_to_{end_date}.xlsx', as_attachment=True)
        return render_template('admin/download_time_range.html', form=form)

    @admin_required
    def clear_database(self):
        if request.method == 'POST':
            confirmation = request.form.get('confirmation')
            if confirmation == 'DELETE ALL':
                try:
                    Record.query.delete()
                    User.query.delete()
                    db.session.commit()
                    flash('Database cleared successfully', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error clearing database: {str(e)}', 'error')
            else:
                flash('Incorrect confirmation phrase', 'error')
            return redirect(url_for('admin_dashboard'))
        return render_template('admin/clear_database.html')


    @admin_required
    def admin_data(self):
        try:
            page = request.args.get('page', 1, type=int)
            per_page = 25
            records = Record.query.order_by(Record.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
            return render_template('admin/data.html', records=records)
        except Exception as e:
            flash('Error retrieving data for display.', 'error')
            return redirect(url_for('admin_dashboard'))

orcid_app = OrcidApp(__name__)

if __name__ == "__main__":
    orcid_app.run(
        host="0.0.0.0",
        port=5000,
        debug=os.getenv("DEBUG", "false").lower() == "true",
        extra_files=[".env"]
    )