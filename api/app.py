import os
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymsql://notenestuser:notenestpassword@localhost:3306/notenest"

app.config["JWT_SECRET_KEY"] = "secret-key"

# Permitir las peticiones desde el servidor de Angular desde el propio localhost
CORS(app, resources={r"/api/*": {"origins": "http://localhost:4200"}})

db = SQLAlchemy(app)
jwt = JWTManager(app)

##############
## MODELOS ###
##############

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    notes = db.relationship(
        "Note",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan"
    )

    folders = db.relationship(
        "Folder",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan"
    )

class Folder(db.Model):
    __tablename__ = "folders"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    notes = db.relationship(
        "Note",
        backref="folder",
        lazy=True
    )

class Note(db.Model):
    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), default="")
    content = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey("folders.id"), nullable=True)

def error_response(message, status_code):
    return jsonify({"error": message}), status_code

@app.post("/api/register")
def register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return error_response("Enter required information",400)
    
    existing = User.query.filter(or_


