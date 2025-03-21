from flask import Flask, redirect, render_template, request, jsonify, current_app, flash, url_for
from flask_sqlalchemy import SQLAlchemy
import xml.etree.ElementTree as ET
from dotenv import load_dotenv
from datetime import datetime, timezone
from sqlalchemy import Enum
from zoneinfo import ZoneInfo
import pandas as pd
import requests
import re
import os


load_dotenv()
db = SQLAlchemy()
utc_now = datetime.now(timezone.utc)
uk_time = utc_now.astimezone(ZoneInfo("Europe/London"))

class Record(db.Model):
    __tablename__ = 'records'
    id = db.Column(db.Integer, primary_key=True)
    orcid = db.Column(db.String(19), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(500), nullable=False)
    type = db.Column(Enum('publication', 'funding', name='record_type'), nullable=False)
    created_at = db.Column(db.DateTime, default=uk_time, nullable=False)

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


class OrcidApp(BaseFlaskApp):
    def __init__(self, app_name):
        super().__init__(app_name)
        self.app.route("/")(self.home)
        self.app.route("/publications/search")(self.orcid_works_search)
        self.app.route("/fundings/search")(self.orcid_fundings_search)
        self.app.route('/publications', methods=['GET', 'POST'])(self.get_orcid_works_data)
        self.app.route('/fundings', methods=['GET', 'POST'])(self.get_orcid_fundings_data)
        self.app.route('/api/token', methods=['GET', 'POST'])(self.get_access_token)
        self.app.route('/process/publications', methods=['POST'])(self.process_works_form)
        self.app.route('/process/fundings', methods=['POST'])(self.process_fundings_form)
        self.app.secret_key = os.getenv("APP_SECRET_KEY")

    def home(self):
        return render_template("home.html")

    def orcid_works_search(self):
        return render_template("orcid_id_works.html")

    def orcid_fundings_search(self):
        return render_template("orcid_id_fundings.html")

    def _fetch_orcid_token(self):
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


    def get_access_token(self):
        """Route handler for /api/token (returns JSON token)."""
        token = self._fetch_orcid_token()
        if token:
            return jsonify({"access_token": token})
        else:
            return jsonify({"error": "Failed to fetch token"}), 500
        
    def _validate_orcid_id(self, orcid_id):
            """Validates ORCiD format"""
            pattern = r'^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$'
            return re.match(pattern, orcid_id.strip()) is not None
            
    def get_orcid_works_data(self):
        access_token = self._fetch_orcid_token()
        if not access_token:
            return jsonify({"error": "Token failure"}), 500
        
        if request.method == 'POST':
            orcid_id = request.form.get('orcidInput')
            if not self._validate_orcid_id(orcid_id):
                flash("Invalid ORCiD. Use the XXXX-XXXX-XXXX-XXXX format.")
                return redirect(request.referrer)
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
            return render_template('works_results.html', unique_titles=unique_titles, orcidInput=orcid_id)
        else:
            # Error message if the request is not successful
            current_app.logger.info(f'Error: {response.status_code} - {response.text}')
            # Return an error response in JSON format
            return jsonify({"error": f"{response.status_code} - {response.text}"}), response.status_code
            pass

    def get_orcid_fundings_data(self):
        access_token = self._fetch_orcid_token()
        if not access_token:
            return jsonify({"error": "Token failure"}), 500

        if request.method == 'POST':
            orcid_id = request.form.get('orcidInput')
            if not self._validate_orcid_id(orcid_id):
                flash("Invalid ORCiD. Use the XXXX-XXXX-XXXX-XXXX format.")
                return redirect(request.referrer)
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
            return render_template('fundings_results.html', titles=titles)
        else:
            # Handle errors
            current_app.logger.info(f'Error: {response.status_code} - {response.text}')
            return jsonify({"error": f"{response.status_code} - {response.text}"}), response.status_code

    def process_works_form(self):
        selected_titles = request.form.getlist('selected_titles')
        username = request.form.get('username')
        current_app.logger.info(request.form)


        if not re.match(r'^[A-Za-z ]{2,50}$', username):
            flash('Invalid name format', 'error')
            return redirect(url_for('orcid_works_search'))

        try:
            with self.app.app_context():
                for title in selected_titles:
                    record = Record(
                        orcid=request.form.get('orcidInput'),
                        name=username,
                        title=title,
                        type='publication'
                    )
                    db.session.add(record)
                db.session.commit()
            flash('Publications saved successfully', 'success')
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Database error: {str(e)}")
            flash('Error saving publications', 'error')
        
        return redirect('/')


    def process_fundings_form(self):
        selected_titles = request.form.getlist('selected_titles')
        username = request.form.get('username')

        if not re.match(r'^[A-Za-z ]{2,50}$', username):
            flash('Invalid name format', 'error')
            return redirect(url_for('orcid_fundings_search'))

        try:
            with self.app.app_context():
                for title in selected_titles:
                    record = Record(
                        orcid=request.form.get('orcidInput'),
                        name=username,
                        title=title,
                        type='funding'
                    )
                    db.session.add(record)
                db.session.commit()
            flash('Fundings saved successfully', 'success')
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Database error: {str(e)}")
            flash('Error saving fundings', 'error')
        
        return redirect('/')
    
    def process_fundings_form(self):
        selected_titles = request.form.getlist('selected_titles')
        username = request.form.getlist('username')  

        # Create a DataFrame with the selected titles and ORCiD
        df = pd.DataFrame({
            'Selected Titles': selected_titles,
            'ORCiD': [username] * len(selected_titles)
        })

        # Specify the Excel file path
        excel_file_path = 'publications_and_fundings.xlsx'
        
        try:
            # Load the existing Excel file
            existing_df = pd.read_excel(excel_file_path)

            # Append the new data to the existing DataFrame
            updated_df = pd.concat([existing_df, df], ignore_index=True)

            # Write the updated DataFrame to the Excel file
            with pd.ExcelWriter(excel_file_path, engine="openpyxl", mode="a", if_sheet_exists="overlay") as writer:
                updated_df.to_excel(writer, sheet_name= 'Works', index=False)

            # You can also add additional processing logic here

            return redirect('/')  # Redirect back to the form page or any other page

        except FileNotFoundError:
            # If the file doesn't exist, write the DataFrame as a new file
            df.to_excel(excel_file_path, index=False)
            return redirect('/')  # Redirect back to the form page or any other page
            pass

orcid_app = OrcidApp(__name__)

if __name__ == "__main__":
    orcid_app.run(host="0.0.0.0", port=5000)
