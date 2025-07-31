# powershell:
# $env:PYTHONPATH="$pwd;$pwd/SearchApp"; pytest tests/Testing.py -v
# bash:
# PYTHONPATH="$PWD:$PWD/SearchApp" pytest tests/test_main.py -v

import os
import sys
import pytest
from unittest.mock import patch, MagicMock

# add both the parent directory and SearchApp to python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'SearchApp'))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("APP_SECRET_KEY", "test_secret_key")
os.environ.setdefault("ORCID_CLIENT_ID", "dummy_client_id")
os.environ.setdefault("ORCID_CLIENT_SECRET", "dummy_client_secret")
os.environ.setdefault("ORCID_REDIRECT_URI", "https://example.com/callback")

from SearchApp.ORCiD_API_App import OrcidApp
from SearchApp.utils import validate_orcid_id, normalise_title, cache_fetcher


def test_validate_orcid_id_valid():
    assert validate_orcid_id("0000-0002-1825-0097") is True
    assert validate_orcid_id("0000-0001-2345-678X") is True


def test_validate_orcid_id_invalid():
    invalid_ids = [
        "0000-0002-1825-009",   # too short
        "0000/0002/1825/0097",  # wrong separators
        "abcd-0002-1825-0097",  # letters where numbers expected
        "0000-0002-1825-00977", # too long
        "",                     # empty string
        "invalid"              # completely invalid
    ]
    for inval in invalid_ids:
        assert validate_orcid_id(inval) is False


def test_normalise_title():
    assert normalise_title("The Great Paper") == "great paper"
    assert normalise_title("A Study of Something") == "study of something"
    assert normalise_title("An Analysis") == "analysis"
    # test special characters
    assert normalise_title("Paper: A Study!") == "paper a study"
    # edge cases
    assert normalise_title("") == ""
    assert normalise_title(None) == ""
    assert normalise_title(123) == ""  # non-string input

def app():
    test_instance = OrcidApp("SearchApp.ORCiD_API_App")
    application = test_instance.app
    application.config.update(
        TESTING=True, 
        WTF_CSRF_ENABLED=False,
        SECRET_KEY='test-secret-key'
    )
    
    search_app_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'SearchApp')
    application.template_folder = os.path.join(search_app_dir, 'templates')
    
    return application


@pytest.fixture
def client():
    return app().test_client()


def test_home_route_loads(client):
    response = client.get("/", follow_redirects=True)
    assert response.status_code == 200


@pytest.mark.skip("Currently patch is broken (mock not applied due to class load order): need to update test")
@patch('SearchApp.utils.fetch_orcid_token')
def test_get_access_token_success(mock_fetch_token, client):
    mock_fetch_token = MagicMock()
    mock_fetch_token.return_value = "dummy_access_token"
    OrcidApp.fetch_orcid_token = mock_fetch_token
    response = client.post("/api/token")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["access_token"] == "dummy_access_token"

@pytest.mark.skip("Currently patch is broken (mock not applied due to class load order): need to update test")
@patch('SearchApp.utils.fetch_orcid_token')
def test_get_access_token_failure(mock_fetch_token, client):
    mock_fetch_token.return_value = None
    response = client.post("/api/token")
    assert response.status_code == 500
    json_data = response.get_json()
    assert "error" in json_data


def test_admin_dashboard_requires_login(client):
    response = client.get("/admin/dashboard", follow_redirects=False)
    assert response.status_code == 302


def test_admin_login_page_loads(client):
    response = client.get("/admin/login")
    assert response.status_code == 200
    assert b"Admin Login" in response.data


@patch('SearchApp.ORCiD_API_App.requests.post')
def test_invalid_orcid_validation(mock_post, client):
    # mock the token fetch for the internal API call
    mock_post.return_value.json.return_value = {"access_token": "dummy_token"}
    mock_post.return_value.raise_for_status.return_value = None
    
    # test with clearly invalid ORCID format
    response = client.post("/publications", data={"orcidInput": "invalid"}, follow_redirects=False)
    
    # should redirect back to sso page
    assert response.status_code == 302
    assert "/publications/sso" in response.headers.get("Location", "")


def test_cache_fetcher_utility():
    orcid_id = "0000-0002-1825-0097"
    cache_key = cache_fetcher(orcid_id)
    assert cache_key == f"orcid_works_{orcid_id}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 