from ORCiD_API_App import orcid_app, db
from flask_migrate import Migrate
import os

app = orcid_app.app
migrate = Migrate(app, db, directory=os.path.join(os.path.dirname(__file__), 'migrations'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)