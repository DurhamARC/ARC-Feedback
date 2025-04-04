from ORCiD_API_App import orcid_app, db
from flask_migrate import Migrate

app = orcid_app.app
migrate = Migrate(app, db)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)