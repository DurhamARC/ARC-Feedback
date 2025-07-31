from flask import Flask, redirect, render_template, request, current_app, flash, url_for, session, abort, send_file
from wtforms import StringField, PasswordField, SubmitField, DateField
from wtforms.validators import DataRequired, Length
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import xml.etree.ElementTree as ET
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_caching import Cache
from flask_wtf import FlaskForm
from datetime import timedelta
from dotenv import load_dotenv
from io import BytesIO
import pandas as pd
import requests
import logging
import secrets
import click
import re
import os

# load environment variables from the .env file
load_dotenv()

# utility functions
from utils import no_publications, no_fundings, get_access_token, initiate_orcid_auth, handle_orcid_callback
from utils import get_works_from_orcid, get_fundings_from_orcid, get_name_from_orcid
from utils import fetch_orcid_token, validate_orcid_id, normalise_title, sanitise_input
from utils import cache_fetcher, admin_required, handle_errors, reset_publications

# models and database setup (ensures 'db' is initialised)
from models import db, User, Record, Admin, Feedback

class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')

class DateRangeForm(FlaskForm):
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Download')

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

class OrcidApp(BaseFlaskApp):
    def __init__(self, app_name):
        super().__init__(app_name)
        
        self.app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY')
        self.app.config['WTF_CSRF_TIME_LIMIT'] = 900
        self.csrf = CSRFProtect(self.app)

        self._limiter = Limiter(
            get_remote_address,
            app=self.app,
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
        self.app.route("/publications/sso")(self.orcid_works_search)
        self.app.route("/about")(self.about)
        self.app.route("/thankyou", methods=['GET', 'POST'])(
            self.thankyou
        )
        self.app.route("/form", methods=['GET', 'POST'])(
            self._limiter.limit("10 per minute")(self.info_form)
        )
        self.app.route('/publications', methods=['GET', 'POST'])(
            self._limiter.limit("10 per minute")(self.get_orcid_works_data)
        )
        self.app.route('/fundings', methods=['GET', 'POST'])(
            self._limiter.limit("10 per minute")(self.get_orcid_fundings_data)
        )
        self.app.route('/publications/empty', methods=['GET', 'POST'])(no_publications)
        self.app.route('/fundings/empty', methods=['GET', 'POST'])(no_fundings)
        self.app.route('/api/token', methods=['GET', 'POST'])(get_access_token)
        self.app.route('/process/publications', methods=['POST'])(self.process_works_form)
        self.app.route('/process/fundings', methods=['POST'])(self.process_fundings_form)
        self.app.route('/auth/orcid')(initiate_orcid_auth)
        self.app.route('/auth/orcid/callback')(handle_orcid_callback)
        self.app.route('/admin/login', methods=['GET', 'POST'])(self.admin_login)
        self.app.route('/admin/logout')(self.admin_logout)
        self.app.route('/admin/dashboard')(self.admin_dashboard)
        self.app.route('/admin/download/all')(self.download_all)
        self.app.route('/admin/download/time_range', methods=['GET', 'POST'])(self.download_time_range)
        self.app.route('/admin/clear_database', methods=['GET', 'POST'])(self.clear_database)
        self.app.route('/admin/data')(self.admin_data)
        self.app.route('/reset/publications')(reset_publications)

    @handle_errors
    def home(self):
        return render_template("home.html")

    @handle_errors
    def orcid_works_search(self):
        return render_template("orcid_id_works.html", enable_orcid_login=os.getenv('ENABLE_ORCID_LOGIN', 'true').lower() in ('true'), debug_mode=current_app.debug)

    @handle_errors
    def about(self):
        return render_template("about.html")

    @handle_errors
    def info_form(self):
        if request.method == 'GET':
            if 'orcid_id' in session:
                orcid_id = session['orcid_id']
            else:
                flash("Please log in with ORCID.", "info")
                return redirect(url_for('orcid_works_search'))

        if request.method == 'POST' and request.form.get('action') == 'submit':
            try:
                raw_feedback = request.form.get('feedback')
                feedback = sanitise_input(raw_feedback) if raw_feedback else ""
                orcid = session['orcid_id']
                submission_id = session.get('current_submission_id')

                if feedback and orcid and submission_id:
                    db.session.add(Feedback(
                        text=feedback, 
                        orcid=orcid,
                        submission_id=submission_id
                    ))
                    db.session.commit()
                    return redirect(url_for('thankyou'))
                else:
                    flash('Feedback cannot be empty.', 'error')
                    return redirect(url_for('info_form')) 
                    
            except Exception:
                logging.exception("Error while saving the message:")
                flash('An error occurred while saving the message. Please try again.', 'error')
                return redirect(url_for('orcid_works_search'))
                
        return render_template("form.html")


    @handle_errors
    def thankyou(self):
        return render_template("thankyou.html")

    @handle_errors
    def get_orcid_works_data(self):
        orcid_id = None

        if request.method == 'GET':
            if 'orcid_id' in session:
                orcid_id = session['orcid_id']
            else:
                flash("Please log in with ORCID.", "info")
                return redirect(url_for('no_publications'))

        elif request.method == 'POST':
            orcid_id = request.form.get('orcidInput')
            if not validate_orcid_id(orcid_id):
                flash("Invalid ORCiD format submitted. Use XXXX-XXXX-XXXX-XXXX.", "error")
                return redirect(url_for('orcid_works_search'))

            session['orcid_id'] = orcid_id
            session.permanent = True
        else:
            abort(405)

        access_token = fetch_orcid_token()
        if not access_token:
            flash("Could not authenticate with the ORCID service at this time. Please try again later.", "error")
            return redirect(url_for('orcid_works_search'))

        cache_key = f"orcid_works_{orcid_id}"
        cached_data = self._cache.get(cache_key)
        if cached_data:
            username = cached_data.get('name', '')
            session_orcid = session.get('orcid_id', orcid_id)
            return render_template('works_results.html',
                                   unique_titles=cached_data.get('titles', []),
                                   username=username,
                                   orcidInput=orcid_id,
                                   orcidID=session_orcid)
        
        try:
            session["full_name"] = name = get_name_from_orcid(orcid_id, access_token)
            unique_titles = get_works_from_orcid(orcid_id, access_token)

            if len(unique_titles) == 0:
                current_app.logger.error(f"No publication has been found in your ORCiD record.", "info")
                return redirect(url_for('no_publications'))
            
            cache_data = {'titles': unique_titles, 'name': name}
            self._cache.set(cache_key, cache_data, timeout=30)

            session_orcid = session.get('orcid_id', orcid_id)
            return render_template('works_results.html',
                                   unique_titles=unique_titles,
                                   username=name,
                                   orcidID=session_orcid)

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 404:
                flash(f"Could not find an ORCID record matching {orcid_id}. Please check the ID.", "error")
            elif status_code == 401 or status_code == 403:
                flash("Authorization error with ORCID. Please check credentials or contact support.", "error")
                self._cache.delete_memoized(fetch_orcid_token)
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
        orcid_id = None

        if request.method == 'GET':
            if 'orcid_id' in session:
                orcid_id = session['orcid_id']
            else:
                flash("Please log in with ORCID or enter your ORCID ID on the search page.", "error")
                return redirect(url_for('orcid_works_search'))

        access_token = fetch_orcid_token()
        if not access_token:
            flash("Could not authenticate with the ORCID service at this time. Please try again later.", "error")
            return redirect(url_for('orcid_works_search'))

        works_cache_key = cache_fetcher(orcid_id)
        fundings_cache_key = f"orcid_fundings_{orcid_id}"

        cached_data_works = self._cache.get(works_cache_key)
        cached_data_fundings = self._cache.get(fundings_cache_key)

        if cached_data_fundings:
            session_orcid = session.get('orcid_id', orcid_id)
            return render_template(
                'fundings_results.html',
                unique_titles=cached_data_fundings.get('titles', []),
                username=cached_data_works.get('name', '') if cached_data_works else '',
                orcidInput=orcid_id,
                orcidID=session_orcid
            )

        try:
            name = session.get("full_name")
            titles = get_fundings_from_orcid(orcid_id, access_token)

            if not titles:
                return redirect(url_for('no_fundings'))
            else:
                normalized = {normalise_title(t): t for t in titles}
                unique_titles = list(normalized.values())

            self._cache.set(fundings_cache_key, {'titles': unique_titles, 'name': name}, timeout=30)

            session_orcid = session.get('orcid_id', orcid_id)
            return render_template(
                'fundings_results.html',
                unique_titles=unique_titles,
                username=name,
                orcidInput=orcid_id,
                orcidID=session_orcid
            )

        except requests.exceptions.HTTPError as e:
            status = e.response.status_code
            if status == 404:
                flash(
                    f"No funding found for ORCID {orcid_id}, or the ORCID ID itself could not be found.",
                    "info"
                )
                self._cache.delete(works_cache_key)
                self._cache.delete(fundings_cache_key)
                return render_template(
                    'fundings_results.html',
                    unique_titles=[],
                    username='',
                    orcidInput=orcid_id
                )
            elif status in (401, 403):
                flash("Authorization error with ORCID. Please check credentials or contact support.", "error")
                self._cache.delete_memoized(fetch_orcid_token)
                return redirect(url_for('orcid_works_search'))
            else:
                flash(f"Error fetching funding data from ORCID (Code: {status}). Please try again later.", "error")
                return redirect(url_for('orcid_works_search'))

        except requests.exceptions.RequestException:
            flash("Could not connect to the ORCID service for fundings. Please check your network or try again later.", "error")
            return redirect(url_for('orcid_works_search'))

        except ET.ParseError:
            flash("Received invalid data format from ORCID for fundings. Please try again.", "error")
            return redirect(url_for('orcid_works_search'))

        except Exception as exc:
            current_app.logger.error(f"Unexpected error in get_orcid_fundings_data: {exc}")
            flash("An unexpected error occurred while processing your fundings.", "error")
            return redirect(url_for('orcid_works_search'))

    def process_works_form(self):
        selected_titles = request.form.getlist('selected_titles')
        username = request.form.get('username', '').strip()
        action = request.form.get('action')

        if not selected_titles:
            pass

        if not os.getenv('ENABLE_ORCID_LOGIN'):
            orcid_input = request.form.get("orcidInput", "").strip()
            if not orcid_input:
                flash('Invalid or missing ORCID ID.', 'error')
                return redirect(url_for('orcid_works_search'))
        else:
            orcid_input = request.form.get("orcidID", "").strip()

        if username and len(username) > 201:
            flash('Invalid characters in name or name too long/short.', 'error')
            return redirect(url_for('orcid_works_search'))

        try:
            with self.app.app_context():
                user = User.query.filter_by(orcid=orcid_input).first()
                if not user:
                    user_name_to_save = username or "Name not provided"
                    user = User(orcid=orcid_input, name=user_name_to_save)
                    db.session.add(user)
                elif username and user.name != username:
                    user.name = username

                submission_id = secrets.token_urlsafe(16)
                session['current_submission_id'] = submission_id

                saved_count = 0
                if not action == "skip":
                    for title in selected_titles:
                        record = Record(
                            title=title,
                            type='publication',
                            orcid=orcid_input,
                            users=user,
                            submission_id=submission_id
                        )
                        db.session.add(record)
                        saved_count += 1

                    if saved_count:
                        db.session.commit()
                    else:
                        logging.debug("No new fundings were selected or saved.")
                else:
                    pass

        except Exception:
            db.session.rollback()
            logging.exception("Error saving publications:")
            flash('An error occurred while saving the publications. Please try again.', 'error')
            return redirect(url_for('orcid_works_search'))

        return redirect(url_for('get_orcid_fundings_data'))

    def process_fundings_form(self):
        selected_titles = request.form.getlist('selected_titles')
        username = request.form.get('username', '').strip()
        action = request.form.get('action')

        if not selected_titles:
            pass

        if not os.getenv('ENABLE_ORCID_LOGIN'):
            orcid_input = request.form.get("orcidInput")
            if not orcid_input:
                flash('Invalid or missing ORCID ID.', 'error')
                return redirect(url_for('orcid_works_search'))
        else:
            orcid_input = request.form.get("orcidID", "").strip()

        if username and not re.match(r"^(n/a|[a-zA-Zà-ÿ.' -]{1,100})$", username, re.IGNORECASE):
            flash('Invalid characters in name or name too long/short.', 'error')
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

                submission_id = session.get('current_submission_id')

                saved_count = 0
                if not action == "skip":
                    for title in selected_titles:
                        record = Record(
                            title=title,
                            type='funding',
                            orcid=orcid_input,
                            users=user,
                            submission_id=submission_id
                        )
                        db.session.add(record)
                        saved_count += 1

                    if saved_count > 0:
                        db.session.commit()
                        logging.debug(f'{saved_count} funding record(s) saved successfully!', 'success')
                    else:
                        logging.debug("No new fundings were selected or saved.")
                else:
                    pass

        except Exception:
            db.session.rollback()
            flash('An error occurred while saving the funding records. Please try again.', 'error')
            return redirect(url_for('orcid_works_search'))

        return redirect(url_for('info_form'))

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
        feedback = Feedback.query.all()
        users_data = [{'id': u.id, 'orcid': u.orcid, 'name': u.name, 'created_at': u.created_at} for u in users]
        records_data = [{'id': r.id, 'orcid': r.orcid, 'title': r.title, 'type': r.type, 'created_at': r.created_at} for r in records]
        feedback_data = [{'id': f.id, 'text': f.text, 'orcid': f.orcid, 'created_at': f.created_at, 'submission_id': f.submission_id} for f in feedback]
        df_users = pd.DataFrame(users_data)
        df_records = pd.DataFrame(records_data)
        df_feedback = pd.DataFrame(feedback_data)
        df_data = pd.concat([df_users, df_records, df_feedback], axis=1)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df_users.to_excel(writer, sheet_name='Users', index=False)
            df_records.to_excel(writer, sheet_name='Records', index=False)
            df_feedback.to_excel(writer, sheet_name='Feedback', index=False)
            df_data.to_excel(writer, sheet_name='Data', index=False)
            
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
            feedback = Feedback.query.filter(Feedback.created_at.between(start_date, end_date)).all()
            users_data = [{'id': u.id, 'orcid': u.orcid, 'name': u.name, 'created_at': u.created_at} for u in users]
            records_data = [{'id': r.id, 'orcid': r.orcid, 'title': r.title, 'type': r.type, 'created_at': r.created_at} for r in records]
            feedback_data = [{'id': f.id, 'text': f.text, 'orcid': f.orcid, 'created_at': f.created_at, 'submission_id': f.submission_id} for f in feedback]
            df_users = pd.DataFrame(users_data)
            df_records = pd.DataFrame(records_data)
            df_feedback = pd.DataFrame(feedback_data)
            df_data = pd.concat([df_users, df_records, df_feedback], axis=1)
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                df_users.to_excel(writer, sheet_name='Users', index=False)
                df_records.to_excel(writer, sheet_name='Records', index=False)
                df_feedback.to_excel(writer, sheet_name='Feedback', index=False)
                df_data.to_excel(writer, sheet_name='Data', index=False)
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
                    Feedback.query.delete()
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

            records = db.session.query(
                Record.id, 
                Record.orcid, 
                User.name, 
                Record.title, 
                Record.type, 
                Record.created_at,
                Feedback.text
            ) \
            .join(User, User.orcid == Record.orcid) \
            .outerjoin(
                Feedback, 
                db.and_(
                    Feedback.submission_id == Record.submission_id,
                    Feedback.orcid == Record.orcid
                )
            ) \
            .order_by(Record.created_at.desc()) \
            .paginate(page=page, per_page=per_page, error_out=False)
            
            return render_template('admin/data.html', records=records)
            
        except Exception as e:
            current_app.logger.error(f"Error: {str(e)}")
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