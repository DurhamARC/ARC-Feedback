from flask import Flask, redirect, render_template, request, jsonify
import requests
import json
import xml.etree.ElementTree as ET
import pandas as pd

class BaseFlaskApp:
    def __init__(self, app_name):
        self.app = Flask(app_name)

    def run(self):
        self.app.run(debug=True)

class OrcidApp(BaseFlaskApp):
    def __init__(self, app_name):
        super().__init__(app_name)

        self.app.route("/")(self.home)
        self.app.route("/orcid_works_search")(self.orcid_works_search)
        self.app.route("/orcid_fundings_search")(self.orcid_fundings_search)
        self.app.route('/orcid/works', methods=['GET', 'POST'])(self.get_orcid_works_data)
        self.app.route('/orcid/fundings', methods=['GET', 'POST'])(self.get_orcid_fundings_data)
        self.app.route('/api/token', methods=['GET', 'POST'])(self.get_access_token)
        self.app.route('/process_works_form', methods=['POST'])(self.process_works_form)
        self.app.route('/process_fundings_form', methods=['POST'])(self.process_fundings_form)

    def home(self):
        return render_template("home.html")

    def orcid_works_search(self):
        return render_template("orcid_id_works.html")

    def orcid_fundings_search(self):
        return render_template("orcid_id_fundings.html")

    # NEW HELPER METHOD
    def _fetch_orcid_token(self):
        """Fetches ORCID access token using client credentials."""
        url = "https://orcid.org/oauth/token"
        headers = {"Accept": "application/json"}
        data = {
            "client_id": "APP-P45XX0Q5RRZY08DC",  # Will move to .env later
            "client_secret": "9e402b3a-6989-4447-8dcc-71e14c535e2a",
            "grant_type": "client_credentials",
            "scope": "/read-public"
        }
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            print("Token fetch successful")
            return response.json().get("access_token")
        else:
            print(f"Token fetch failed: {response.status_code} - {response.text}")
            return None

    # UPDATED ROUTE HANDLER
    def get_access_token(self):
        """Route handler for /api/token (returns JSON token)."""
        token = self._fetch_orcid_token()
        if token:
            return jsonify({"access_token": token})
        else:
            return jsonify({"error": "Failed to fetch token"}), 500

    def get_orcid_works_data(self):
        # Fetch token dynamically
        access_token = self._fetch_orcid_token()
        if not access_token:
            return jsonify({"error": "Failed to obtain ORCID access token"}), 500

        if request.method == 'POST':
            orcid_id = request.form.get('orcidInput')
            url = f'https://pub.orcid.org/v3.0/{orcid_id}/works'
        else:
            url = 'https://pub.orcid.org/v3.0/{ORCID_ID}/works'

        headers = {
            'Content-type': 'application/vnd.orcid+xml',
            'Authorization': f'Bearer {access_token}'  # Use dynamic token
        }

        response = requests.get(url, headers=headers)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Save the XML response to a file
            file_path = 'works_response_data.xml'
            with open(file_path, 'w') as file:
                file.write(response.text)

            # Parse the XML data
            with open(file_path, 'r') as file:
                xml_data = file.read()

            # Define XML namespaces
            namespaces = {
            'activities': 'http://www.orcid.org/ns/activities',
            'common': 'http://www.orcid.org/ns/common',
            'work': 'http://www.orcid.org/ns/work',
            }

            root = ET.fromstring(xml_data)

            # Extract the titles from the XML
            titles = [title.text for title in root.findall('.//common:title', namespaces)]

            # Pass the titles to the template
            return render_template('works_results.html', titles=titles)
        else:
            # Print an error message if the request was not successful
            print(f'Error: {response.status_code} - {response.text}')
            # Return an error response in JSON format
            return jsonify({"error": f"{response.status_code} - {response.text}"}), response.status_code
            pass

    def get_orcid_fundings_data(self):
        # Fetch token dynamically
        access_token = self._fetch_orcid_token()
        if not access_token:
            return jsonify({"error": "Failed to obtain ORCID access token"}), 500

        if request.method == 'POST':
            # Get the ORCID ID from the form
            orcid_id = request.form.get('orcidInput')
            url = f'https://pub.orcid.org/v3.0/{orcid_id}/fundings'
        else:
            # Default URL (might remove this or handle it)
            url = 'https://pub.orcid.org/v3.0/{ORCID_ID}/fundings'

        headers = {
            'Content-type': 'application/vnd.orcid+xml',
            'Authorization': f'Bearer {access_token}'  # Dynamic token
        }

        # Make the GET request
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            file_path = 'fundings_response_data.xml'
            with open(file_path, 'w') as file:
                file.write(response.text)

            # Parse XML
            with open(file_path, 'r') as file:
                xml_data = file.read()

            namespaces = {
                'activities': 'http://www.orcid.org/ns/activities',
                'common': 'http://www.orcid.org/ns/common',
                'work': 'http://www.orcid.org/ns/work',
            }

            root = ET.fromstring(xml_data)

            # Extract titles
            titles = [title.text for title in root.findall('.//common:title', namespaces)]

            # Return the same template
            return render_template('fundings_results.html', titles=titles)
        else:
            # Handle errors
            print(f'Error: {response.status_code} - {response.text}')
            return jsonify({"error": f"{response.status_code} - {response.text}"}), response.status_code

    def process_works_form(self):
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
            updated_df.to_excel(excel_file_path, index=False, sheet_name='Sheet1')

            # Additional processing logic possible here 

            return redirect('/')  # Redirect back to the form page or any other page

        except FileNotFoundError:
            # If the file doesn't exist, write the DataFrame as a new file
            df.to_excel(excel_file_path, index=False)
            return redirect('/')  # Redirect back to the form page or any other page
            pass
    
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
            updated_df.to_excel(excel_file_path, index=False, sheet_name='Sheet2')

            # You can also add additional processing logic here

            return redirect('/')  # Redirect back to the form page or any other page

        except FileNotFoundError:
            # If the file doesn't exist, write the DataFrame as a new file
            df.to_excel(excel_file_path, index=False)
            return redirect('/')  # Redirect back to the form page or any other page
            pass

if __name__ == "__main__":
    orcid_app = OrcidApp(__name__)
    orcid_app.run()
