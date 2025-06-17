1. Ensure you have all dependencies installed:
   pip install -r requirements.txt

2. Run the tests from the project root directory:
   $env:PYTHONPATH="$pwd;$pwd/SearchApp"; pytest tests/Testing.py -v


3. All 10 tests should pass, covering:
   - Input validation
   - Core API endpoints
   - Authentication flows
   - Error handling
   - Template rendering 