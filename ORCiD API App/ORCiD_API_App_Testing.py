import unittest
from flask import Flask
from ORCiD_API_App import BaseFlaskApp

class TestOrcidApp(unittest.TestCase):
    def setUp(self):
        # Create a test client and set it as an attribute of the test class
        self.app = BaseFlaskApp(__name__).app.test_client()

    def test_get_orcid_data_success(self):
        # Replace with a valid ORCID ID for testing
        orcid_id = '0009-0000-9308-8766'

        # Simulate a POST request to the /api/orcid endpoint
        response = self.app.post('/api/orcid', data={'orcidInput': orcid_id})

        # Assert that the response status code is 200
        self.assertEqual(response.status_code, 200)

        # Assert that the response content type is XML
        self.assertTrue(response.content_type.startswith('application/xml') or response.content_type.startswith('text/xml'))

        # Add assertions to check the XML content if needed
        # Example: Check if a specific XML element exists in the response
        xml_content = response.data.decode('utf-8')
        self.assertIn('<common:title>', xml_content)

        # Add more assertions based on the expected XML content

    def test_get_orcid_data_failure(self):
        # Simulate a POST request without providing an ORCID ID to simulate failure
        response = self.app.post('/api/orcid')

        # Assert that the response status code indicates failure (e.g., 400 or 500)
        self.assertNotEqual(response.status_code, 404)

        # Assert that the response content type is XML
        self.assertTrue(response.content_type.startswith('application/xml') or response.content_type.startswith('text/xml'))

        # Add assertions to check the XML content if needed
        # Example: Check if a specific XML element exists in the response
        xml_content = response.data.decode('utf-8')
        self.assertIn('<error>', xml_content)

        # Add more assertions based on the expected XML content

if __name__ == '__main__':
    unittest.main()
