from flask import Flask, redirect, url_for, render_template, request, jsonify
import requests
import json

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")

def load_json_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

@app.route('/api/oauth2', methods=['GET', 'POST'])
def get_oauth_data():
    # Access token for the ORCiD API
    access_token = '80e9d501-fbe2-46d2-abcb-d196f1f7ba86'

    if request.method == 'POST':
        # Get the ORCID ID from the form
        orcid_id = request.form.get('orcidInput')

        # URL for the GET request with the ORCID ID as a parameter
        url = f'https://pub.sandbox.orcid.org/v3.0/{orcid_id}/educations'
    else:
        # Default URL for the GET request without the ORCID ID
        url = 'https://pub.sandbox.orcid.org/v3.0/{ORCID_ID}/educations'

    # Headers including Content-type and Authorization with Bearer token
    headers = {
        'Content-type': 'application/vnd.orcid+json',
        'Authorization': f'Bearer {access_token}'
    }

    # Make the GET request
    response = requests.get(url, headers=headers)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Parse the JSON response
        response_dict = json.loads(response.text)

        # Save the JSON data to a file (optional)
        file_path = 'response_data.json'
        with open(file_path, 'w') as file:
            json.dump(response_dict, file, indent=2)

        # Load the JSON data from the file (optional)
        data = json.load(open(file_path))

        # Return the rendered template with the parsed JSON data
        return render_template("oauth.html", response=data, url=url)
    else:
        # Print an error message if the request was not successful
        print(f'Error: {response.status_code} - {response.text}')

@app.route('/index')
def index():
    return render_template('index2.html')

@app.route('/process_form', methods=['POST'])
def process_form():
    # Access the form data using request.form
    ORCID_ID = request.form['ORCID_ID']

    # Convert the data to a Python variable
    # For example, you can simply assign it to a variable
    python_variable = ORCID_ID

    # Now you can do whatever you want with the Python variable
    # In this example, we'll just print it
    print("ORCiD ID:", python_variable)

    # You can also pass the variable to another template or redirect to another page
    # For simplicity, let's just render a template with the variable
    return render_template('result.html', python_variable=python_variable)

if __name__ == "__main__":
    app.run(debug=True)



    