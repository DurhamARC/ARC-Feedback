from flask import Flask, redirect, url_for, render_template, request, jsonify
import requests
import json
import xml.etree.ElementTree as ET
import pandas as pd

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route('/api/orcid', methods=['GET', 'POST'])
def get_orcid_data():
    # Access token for the ORCiD API (replace with your actual method of obtaining the token)
    access_token = '21ca369a-65f6-4b6c-aed5-44a5e85b0ee4'

    if request.method == 'POST':
        # Get the ORCID ID from the form
        orcid_id = request.form.get('orcidInput')

        # URL for the GET request with the ORCID ID as a parameter
        url = f'https://pub.orcid.org/v3.0/{orcid_id}/works'
    else:
        # Default URL for the GET request without the ORCID ID (replace {ORCID_ID} with an actual ORCID ID)
        url = 'https://pub.orcid.org/v3.0/{ORCID_ID}/works'

    # Headers including Content-type and Authorization with Bearer token
    headers = {
        'Content-type': 'application/vnd.orcid+xml',  # Change content-type to XML
        'Authorization': f'Bearer {access_token}'
    }

    # Make the GET request
    response = requests.get(url, headers=headers)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Save the XML response to a file (optional)
        file_path = 'response_data.xml'
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
        return render_template('oauth.html', titles=titles)
    else:
        # Print an error message if the request was not successful
        print(f'Error: {response.status_code} - {response.text}')
        # Return an error response in JSON format
        return jsonify({"error": f"{response.status_code} - {response.text}"}), response.status_code

@app.route('/api/token', methods=['GET', 'POST'])
def get_access_token():
    url = "https://orcid.org/oauth/token"
    headers = {
        "Accept": "application/json"
    }

    data = {
        "client_id": "APP-P45XX0Q5RRZY08DC",
        "client_secret": "9e402b3a-6989-4447-8dcc-71e14c535e2a",
        "grant_type": "client_credentials",
        "scope": "/read-public"
    }

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        # Request was successful, parse the JSON response
        response_data = response.json()
        access_token = response_data.get("access_token")
        # You might want to return the access token instead of printing it
        return jsonify({"access_token": access_token})
    else:
        # Request failed, print the error status code and message
        print(f"Error: {response.status_code} - {response.text}")
        # You might want to return an error response in a real application
        return jsonify({"error": f"{response.status_code} - {response.text}"}), response.status_code

@app.route('/process_form', methods=['POST'])
def process_form():
    selected_titles = request.form.getlist('selected_titles')
    username = request.form.getlist('username')  

    # Create a DataFrame with the selected titles and ORCiD
    df = pd.DataFrame({
        'Selected Titles': selected_titles,
        'ORCiD': [username] * len(selected_titles)
    })

    # Specify the Excel file path
    excel_file_path = 'selected_titles.xlsx'

    try:
        # Load the existing Excel file
        existing_df = pd.read_excel(excel_file_path)

        # Append the new data to the existing DataFrame
        updated_df = pd.concat([existing_df, df], ignore_index=True)

        # Write the updated DataFrame to the Excel file
        updated_df.to_excel(excel_file_path, index=False, sheet_name='Sheet1')

        # You can also add additional processing logic here

        return redirect('/')  # Redirect back to the form page or any other page

    except FileNotFoundError:
        # If the file doesn't exist, write the DataFrame as a new file
        df.to_excel(excel_file_path, index=False)
        return redirect('/')  # Redirect back to the form page or any other page

if __name__ == "__main__":
    app.run(debug=True)



    