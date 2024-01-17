from flask import Flask, redirect, url_for, render_template, request, jsonify
import requests
import json

app = Flask(__name__)

@app.route('/api/oauth')
def get_oauth_data():
    # Access token for the ORCiD API
    access_token = 'db8a13cb-49cb-418e-8004-6b4b9d1beea6'

    # URL for the GET request
    url = 'https://pub.sandbox.orcid.org/v3.0/0009-0006-4684-0381/record'

    # Headers including Content-type and Authorization with Bearer token
    headers = {
        'Content-type': 'application/vnd.orcid+json',
        'Authorization': f'Bearer {access_token}'
    }

    # Make the GET request
    response = requests.get(url, headers=headers)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Print the response content (in this case, the JSON data)
        response_dict = json.loads(response.text)
        return render_template("oauth.html", response=response.__dict__, url=url)
        print(response)
    else:
        # Print an error message if the request was not successful
        print(f'Error: {response.status_code} - {response.text}')

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/test")
def test():
    return render_template("test.html")

def load_json_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

@app.route('/api/oauth2', methods=['GET', 'POST'])
def get_oauth_data2():
    # Access token for the ORCiD API
    access_token = '80e9d501-fbe2-46d2-abcb-d196f1f7ba86'

    # URL for the GET request
    url = 'https://pub.sandbox.orcid.org/v3.0/0009-0006-4684-0381/educations'

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

        # Save the JSON data to a file
        file_path = 'response_data.json'
        with open(file_path, 'w') as file:
            json.dump(response_dict, file, indent=2)

        # Load the JSON data from the file
        data = load_json_file(file_path)

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
    input_data = request.form['input_data']

    # Convert the data to a Python variable
    # For example, you can simply assign it to a variable
    python_variable = input_data

    # Now you can do whatever you want with the Python variable
    # In this example, we'll just print it
    print("Input data:", python_variable)

    # You can also pass the variable to another template or redirect to another page
    # For simplicity, let's just render a template with the variable
    return render_template('result.html', python_variable=python_variable)

if __name__ == "__main__":
    app.run(debug=True)



    