from ORCiD_API_App import re, redirect, current_app, flash, url_for, session, requests, ET, os, render_template, secrets, abort, request
from flask import jsonify
from models import Record, db
from functools import wraps
import bleach

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

def sanitise_input(text):
    if not text:
        return ""
    
    # use 'bleach' to clean the input text by stripping all tags
    cleaned = bleach.clean(text, tags=[], attributes={}, strip=True)
    return cleaned[:300]

def validate_orcid_id(orcid_id):
    pattern = r'^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$'
    return re.match(pattern, orcid_id.strip()) is not None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

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


def get_name_from_orcid(orcid_id, access_token):
    # https://info.orcid.org/documentation/api-tutorials/api-tutorial-read-data-on-a-record/

    url = f'https://pub.orcid.org/v3.0/{orcid_id}/person'
    headers = {
        'Accept': 'application/vnd.orcid+xml',
        'Authorization': f'Bearer {access_token}'
    }
    response = requests.get(url, headers=headers, timeout=15)
    response.raise_for_status()

    root = ET.fromstring(response.content)
    
    namespaces = {
        'person': 'http://www.orcid.org/ns/person',
        'personal-details': 'http://www.orcid.org/ns/personal-details',
    }
    
    # find the name element in the XML
    name_element = root.find('.//person:name', namespaces)
    
    if name_element is not None:
        # extract given names and family name
        given_names_elem = name_element.find('personal-details:given-names', namespaces)
        family_name_elem = name_element.find('personal-details:family-name', namespaces)
        
        given_names = given_names_elem.text if given_names_elem is not None else ""
        family_name = family_name_elem.text if family_name_elem is not None else ""
        
        # combine the names
        full_name = f"{given_names} {family_name}".strip()
        return full_name
    return None

def get_works_from_orcid(orcid_id, access_token):
    url = f'https://pub.orcid.org/v3.0/{orcid_id}/works'
    headers = {
        'Accept': 'application/vnd.orcid+xml',
        'Authorization': f'Bearer {access_token}'
    }
    response = requests.get(url, headers=headers, timeout=15)
    response.raise_for_status()

    namespaces = {
        'common': 'http://www.orcid.org/ns/common',
        'work': 'http://www.orcid.org/ns/work',
    }

    root = ET.fromstring(response.text)

    titles = [title.text for title in root.findall('.//work:title/common:title', namespaces) if title.text]
    normalised_titles = {normalise_title(title): title for title in titles if title}
    return list(normalised_titles.values())

def get_fundings_from_orcid(orcid_id, access_token):
    url = f'https://pub.orcid.org/v3.0/{orcid_id}/fundings'
    headers = {
        'Accept': 'application/vnd.orcid+xml',
        'Authorization': f'Bearer {access_token}'
    }

    response = requests.get(url, headers=headers, timeout=15)
    response.raise_for_status()

    namespaces = {
        'common': 'http://www.orcid.org/ns/common',
        'funding': 'http://www.orcid.org/ns/funding'
    }
    
    root = ET.fromstring(response.text)

    return [
        t.text for t in root.findall('.//funding:title/common:title', namespaces)
        if t.text
    ]

def fetch_orcid_token():
    def inner_fetch():
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
            return flash(f"Error: Request exception inside of fetch_orcid_token: {e}", "error")
    return inner_fetch()

@handle_errors
def reset_publications():
    if 'orcid_id' not in session or 'current_submission_id' not in session:
        flash("Session expired. Please start over.", "error")
        return redirect(url_for('orcid_works_search'))
    orcid_id = session['orcid_id']
    submission_id = session['current_submission_id']
    try:
        Record.query.filter_by(orcid=orcid_id, type='publication', submission_id=submission_id).delete()
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while removing previous selections.", "error")
    return redirect(url_for('get_orcid_works_data'))

@handle_errors
def get_access_token():
    token = fetch_orcid_token()
    if token:
        return jsonify({"access_token": token})
    else:
        return jsonify({"error": "Failed to fetch token", "details": "Check server logs"}), 500

@handle_errors
def cache_fetcher(orcid_id):
    return f"orcid_works_{orcid_id}"

@handle_errors
def no_fundings():
    session_orcid = session.get('orcid_id')
    full_name = session.get("full_name")
    return render_template('fundings_results.html', orcidID=session_orcid, username=full_name)

@handle_errors
def no_publications():
    session_orcid = session.get('orcid_id')
    full_name = session.get("full_name")
    return render_template('works_results.html', orcidID=session_orcid, username=full_name)

@handle_errors
def initiate_orcid_auth():
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
def handle_orcid_callback():
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
    except requests.exceptions.RequestException:
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
    
    return redirect(url_for('get_orcid_works_data'))
