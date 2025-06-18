
from zoneinfo import ZoneInfo
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()
utc_now = datetime.now(timezone.utc)
uk_time = utc_now.astimezone(ZoneInfo("Europe/London"))

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    orcid = db.Column(db.String(19), nullable=False, unique=True, index=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=uk_time, nullable=False, index=True)
    records = db.relationship('Record', backref='users', lazy=True)
    __table_args__ = (
        db.Index('idx_user_orcid_name', 'orcid', 'name'),
    )

class Record(db.Model):
    __tablename__ = 'records'
    id = db.Column(db.Integer, primary_key=True)
    orcid = db.Column(db.String(19), db.ForeignKey('users.orcid'), nullable=False, index=True)
    title = db.Column(db.String(500), nullable=False, index=True)
    type = db.Column(db.Enum('publication', 'funding', name='record_type'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=uk_time, nullable=False, index=True)
    submission_id = db.Column(db.String(32), nullable=False, index=True)
    __table_args__ = (
        db.Index('idx_record_orcid_type', 'orcid', 'type'),
    )

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
