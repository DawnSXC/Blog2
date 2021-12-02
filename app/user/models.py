import login as login
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from datetime import datetime


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(1024), index=True, unique=True, nullable=False)
    phone = db.Column(db.String(11), unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    img = db.Column(db.String(1000))
    gender = db.Column(db.Integer, default=0)
    regtime = db.Column(db.DateTime, default=datetime.now)
    post = db.relationship('Post', backref='user', lazy='dynamic')
    comments = db.relationship('Comment', backref='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __str__(self):
        return self.username


class Suggestion(db.Model):
    __tablename__ = 'suggestion'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(1024), index=True)
    email = db.Column(db.String(120), index=True)
    title = db.Column(db.String(1000))
    description = db.Column(db.Text)
