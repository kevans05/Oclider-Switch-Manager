from time import time

import jwt
from flask import current_app
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, login

from sqlalchemy import func


association_between_user_internet_protocol_address = db.Table(
    "association_between_user_internet_protocol_address",
    db.Model.metadata,
    db.Column("user_id", db.ForeignKey("user.id")),
    db.Column("internet_protocol_address_id", db.ForeignKey("internet_protocol_address.id")),
)

class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))

    jasper_credential = db.relationship("JasperCredential", back_populates="users")

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @login.user_loader
    def load_user(id):
        return User.query.get(int(id))

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            current_app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)


class InternetProtocolAddress(db.Model):
    __tablename__ = "internet_protocol_address"
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(IPAddressType)
