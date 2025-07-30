<img width="100%" alt="roundcorners" src="https://github.com/user-attachments/assets/a0858ef9-d6ff-4028-904e-4356be1b833c" />

# ARC-Feedback

## Description

- This is a Flask web application designed to collect feedback on research outputs that utilised Advanced Research Computing (ARC) resources, platforms, or staff support at Durham University.
- The application enables users to authenticate via ORCID, retrieve their publication and funding data from the ORCID API, and submit feedback on their research outputs.
- It includes an admin interface for managing and downloading the collected data, making it a valuable tool for tracking and analysing research impact.

### Features
- User authentication via ORCID: Secure login using ORCID credentials.
- Retrieval of user's publication and funding data from ORCID: Fetches works and funding records associated with a user's ORCID ID.
- Form for users to provide feedback on their research outputs: Allows users to submit feedback linked to specific submissions.
- Admin interface for managing and downloading collected data: Provides administrators with tools to view, export, and clear data.

### Technologies Used
- Flask: A lightweight Python web framework powering the application.
- SQLAlchemy: Handles database management and object-relational mapping (ORM).
- Flask-WTF: Manages form handling and includes CSRF protection.
- ORCID API: Facilitates user authentication and data retrieval.

## Setup Instructions

Follow these steps to set up and run the application locally:

1. Clone the repository:
```bash
git clone https://github.com/DurhamARC/ARC-Feedback
cd ARC-Feedback
```
2. Set up a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:

   Create a `.env` file in the root directory with the following variables:
```bash
DATABASE_URL=your_database_url
APP_SECRET_KEY=your_secret_key
ORCID_CLIENT_ID=your_orcid_client_id
ORCID_CLIENT_SECRET=your_orcid_client_secret
ORCID_REDIRECT_URI=your_orcid_redirect_uri
ENABLE_ORCID_LOGIN=true
DEBUG=true
```
   Replace placeholders with actual values:
     - `DATABASE_URL`: Use `sqlite:///feedback.db` for local SQLite development or a PostgreSQL URI 
       (`postgresql://user:password@localhost/dbname`) for production, as supported by the `docker-compose.yml` configuration.
     - `APP_SECRET_KEY`: A securely generated secret key (can be generated using `secrets.token_hex(16)` in Python).
     - `ORCID_CLIENT_ID` and `ORCID_CLIENT_SECRET`: Obtain these from your ORCID developer account.
     - `ORCID_REDIRECT_URI`: The URI registered with ORCID (`http://localhost:5000/auth/orcid/callback` for local development).

6. Initialise the database:
   With Flask-Migrate configured in `wsgi.py`, run:
```bash
flask db upgrade
```
   (This applies migrations to create the database tables. Alternatively, running the app once with a valid `DATABASE_URL` will initialise the tables using `db.create_all()` from `ORCiD_API_App.py`)

7. Create an admin user:
   Use the custom CLI command defined in `ORCiD_API_App.py`:
```bash
flask create-admin username password
```
   (Replace `username` and `password` with your desired credentials)

8. Run the application:
```bash
flask run
```
   (The application will be available at `http://localhost:5000`)

Note: For production, consider using a PostgreSQL database (as configured in `docker-compose.yml`) and running with Gunicorn, as specified in `Dockerfile.production`.

## Database Models

The application uses the following database models, as defined in `models.py`:

- User: Represents a user authenticated via ORCID.
  - Fields: `id`, `orcid` (unique ORCID ID), `name`, `created_at` (timestamp in UK time).
- Record: Stores the user's publications or funding records.
  - Fields: `id`, `orcid` (foreign key to User), `title`, `type` (either 'publication' or 'funding'), `created_at`, `submission_id` (links related records and feedback).
- Admin: Represents an administrator for the admin interface.
  - Fields: `id`, `username` (unique), `password_hash` (hashed password).
- Feedback: Stores feedback provided by users.
  - Fields: `id`, `text` (up to 300 characters), `orcid`, `created_at`, `submission_id` (links to Records).

## Security Considerations
- Keep dependencies up to date: Mitigate vulnerabilities, as listed in `requirements.txt`.
- Ensure APP_SECRET_KEY is securely generated: Critical for session security, set via `.env`.
- Limit admin access and use strong passwords: Enforced by hashed passwords in the Admin model.
- Additional measures implemented:
  - CSRF protection via Flask-WTF.
  - Rate limiting with Flask-Limiter
  - Secure session cookies.

## Contributing

- Contributions are welcome! Please submit issues or pull requests.
- For major changes, open an issue first to discuss proposed updates.

## Licence

- This project is licenced under the Mozilla Public License Version 2.0. See the [LICENSE](LICENSE) file for details.
