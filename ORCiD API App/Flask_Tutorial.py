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

@app.route('/api/oauth2')
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
        # Parse the JSON response
        response_dict = json.loads(response.text)

        # Save the JSON data to a file
        file_path = 'response_data.json'
        with open(file_path, 'w') as file:
            json.dump(response_dict, file, indent=2)

        # Return the rendered template
        return render_template("oauth.html", response=response.__dict__, url=url)
    else:
        # Print an error message if the request was not successful
        print(f'Error: {response.status_code} - {response.text}')

if __name__ == "__main__":
    app.run(debug=True)



    