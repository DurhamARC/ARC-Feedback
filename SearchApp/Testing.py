import unittest
from ORCiD_API_App import OrcidApp
from flask import current_app, Flask
import requests

def app():
    app = Flask(__name__)
    return app

class OrcidAppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = OrcidApp(__name__)
        self.client = self.app.app.test_client()

    def test_get_orcid_works_data_multiple_ids(self):
        # List of ORCID IDs to test
        orcid_ids = ['0009-0000-9308-8766', 
                     '0000-0003-0167-080X',
                     '0000-0002-9338-5928',
                     '0000-0002-8300-4861',
                     '0009-0005-7224-7197',
                     '0009-0005-0728-4223',
                     '0000-0000-0000-0001'] #invalid ID

        for orcid_id in orcid_ids:
            # Perform a POST request to the /orcid/works endpoint with the ORCID IDs
            response = self.client.post('/orcid/works', data={'orcidInput': orcid_id})

            # Check if the status code is 200 for valid IDs or not 200 for invalid IDs
            if orcid_id == '0000-0000-0000-0001':
                self.assertNotEqual(response.status_code, 200)
            else:
                self.assertEqual(response.status_code, 200)
    def test_auth_init(self):
        with self.app.app.test_client() as c:
            response = c.get("/auth/orcid")
            print(response)

        #self.assertEqual(self.app.initiate_orcid_auth())
            
    def test_handle_orcid_callback(self):
        with self.app.app.test_client() as c:
            response = c.get("http://127.0.0.1:5000/auth/orcid/callback")
            print(response)
        

if __name__ == '__main__':
    unittest.main(verbosity=2)
