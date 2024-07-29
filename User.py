from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from EncryptDecrypt import EncryptDecrypt, Hash

db = SQLAlchemy()
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(), unique=False, nullable=False)
    file = db.Column(db.String(), unique=True, nullable=True)


with app.app_context():
    db.create_all()
    session = db.session
    session._flushing = False  # Disable flushing on commit
    # ... perform read-only operations ...
    session.commit()  # Safe to commit in read-only mode

class User:

    @staticmethod
    def create_user(email, password):
        # Creates User
        hashed = Hash().hash_password(password)
        with app.app_context():
            new_user = Users(email=email, password=hashed)
            db.session.add(new_user)
            db.session.commit()
        # Creates User's File
        with app.app_context():
            user = db.session.execute(db.select(Users).where(Users.email == email)).scalar()
            user.file = "user" + str(user.id) + ".bin"
            filename = user.file
            db.session.commit()

    @staticmethod
    def check_user(email, password):
        is_valid = True
        hashed = Hash().hash_password(password)
        try:
            with app.app_context():
                find_user = db.session.execute(db.select(Users).where(Users.email == email)).scalar()
                if find_user.password != hashed:
                    is_valid = False
        except:
            is_valid = False

        return is_valid

    @staticmethod
    def find_user(email):
        found = True
        try:
            with app.app_context():
                find_user = db.session.execute(db.select(Users).where(Users.email == email)).scalar()
                if find_user.email != email:
                    found = False
        except:
            found = False

        return found

    @staticmethod
    def get_user(email):
        with app.app_context():
            user = db.session.execute(db.select(Users).where(Users.email == email)).scalar()
            return user

    @staticmethod
    def get_user_file(email):
        if User().find_user(email):
            with app.app_context():
                user = db.session.execute(db.select(Users).where(Users.email == email)).scalar()
                return user.file

