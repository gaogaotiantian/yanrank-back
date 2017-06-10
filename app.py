# coding=utf-8
# python built-in libs
import os
import time
import base64
import hashlib
import json
import functools
import urllib

# SQL stuff
import psycopg2

# Flask
import flask
from flask import Flask, request, render_template
from flask_login import LoginManager
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message

# Initialization
if os.environ.get('DATABASE_URL') != None:
    DATABASE_URL = os.environ.get('DATABASE_URL')
else:
    DATABASE_URL = "postgresql+psycopg2://gaotian:password@localhost:5432/yanrank"
CLOUDINARY_API_SECRET = os.environ.get('CLOUDINARY_API_SECRET')
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
CORS(app)
db = SQLAlchemy(app)
mail = Mail(app)

# ============================================================================
#                                 Decoreator
# ============================================================================

def require(*required_args, **kw_req_args):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kw):
            data = request.get_json()
            if data == None:
                resp = flask.jsonify( msg="No json!")
                resp.status_code = 400
                return resp
            for arg in required_args:
                if arg not in data:
                    resp = flask.jsonify(code=400, msg="wrong args! need "+arg)
                    resp.status_code = 400
                    return resp
            if kw_req_args != None:
                if "login" in kw_req_args:
                    assert('token' in required_args)
                    username = data[kw_req_args["login"]]
                    token = data['token']
                    u = User(username = username, token = token)
                    if not u.valid:
                        resp = flask.jsonify(msg="This action requires login!")
                        resp.status_code = 401
                        return resp
                if "postValid" in kw_req_args:
                    p = Post()
                    if not p.Exist(data[kw_req_args["postValid"]]):
                        resp = flask.jsonify(msg="The reference post is not valid")
                        resp.status.code = 400
                        return resp
            return func(*args, **kw)
        return wrapper
    return decorator

# ============================================================================
#                                Classes 
# ============================================================================
# --------------------------------
#     Database Classes
# --------------------------------
class UserDb(db.Model):
    __tablename__ = 'users'
    username      = db.Column(db.String(50), primary_key=True)
    password      = db.Column(db.String(32))
    token         = db.Column(db.String(32), default="")
    token_exp     = db.Column(db.Integer, default=0)
    email         = db.Column(db.String(50), default="")
    points        = db.Column(db.Integer, default=1000)
    credit        = db.Column(db.Integer, default=0)
    money         = db.Column(db.Integer, default=0)

class ImageDb(db.Model):
    __tablename__ = 'images'
    id            = db.Column(db.Integer, primary_key=True)
    url           = db.Column(db.Text, default="")
    gender        = db.Column(db.String(2), default="f")
    tags          = db.Column(db.String(20), default="")
    rank          = db.Column(db.Integer, default=1000)
    owner         = db.Column(db.String(50), default="")

db.create_all()


# --------------------------------------
#           Flask Classes 
# --------------------------------------
class User:
    def __init__(self, username = "", password = None, token = None):
        self.username = username
        if username != "":
            self.data = UserDb.query.get(username)
        else:
            self.data = None
        self.valid = self.IsValid(password, token)

    def __getitem__(self, key):
        if self.data == None:
            return None
        return self.data.__getattribute__(key)

    def __setitem__(self, key, val):
        if self.data != None:
            self.data.__setattr__(key, val)
            
    def IsValid(self, password, token):
        if self.data == None:
            return False
        else:
            if password == None and token == None:
                return True
            elif token != None:
                return token == self['token'] and self['token_exp'] > time.time()
            elif password != None:
                return hashlib.md5(password).hexdigest() == self['password']
            assert(False)

    def Register(self, data):
        username = data['username']
        password = data['password']
        email    = data['email']
        if len(username) < 2 or len(username) > 50 or \
                len(password) < 8 or len(password) > 50 or \
                len(email) > 50:
            return 400, {"msg": "Invalid parameter"}
        for c in password:
            try:
                num = ord(c)
                if num < 33 or num > 126:
                    return 400, {"msg":"Invalid password charactor"}
            except:
                return 400, {"msg":"Invalid password charactor"}
        if UserDb.query.filter_by(username = username).first() == None:
            token = base64.urlsafe_b64encode(os.urandom(24))
            newUser = UserDb(username = username, 
                    password = hashlib.md5(password).hexdigest(),
                    token = token,
                    email = email,
                    token_exp = time.time() + 3600)
            db.session.add(newUser)
            db.session.commit()
            return 200, {"msg":"Success", "token":token}
        return 400, {"msg":"用户名已被占用"}

    def Login(self, remember):
        if self.valid:
            token = base64.urlsafe_b64encode(os.urandom(24))
            if remember:
                self['token'] = token
                self['token_exp'] = time.time() + 3600*24*30
            else:
                self['token'] = token
                self['token_exp'] = time.time() + 3600
            db.session.commit()
            return 200, {"msg" : "Success!", "username": self['username'], "token": token}
        return 400, {"msg": "用户名或密码错误！"}

    def Logoff(self):
        if self.valid:
            self['token'] = ""
            self['token_exp'] = 0
            db.session.commit()
            return 200, {"msg": "Success"}
        return 400, {"msg": "登出失败！"}

    def ChangePassword(self, data):
        if self.valid:
            if hashlib.md5(data['old_password']).hexdigest() == self['password']:
                self['password'] = hashlib.md5(data['new_password']).hexdigest()
                db.session.commit()
                return 200, {"msg":"Success!"}
            else:
                return 400, {"msg":"Wrong user/password combination!"}

class Image:
    def __init__(self, id = None):
        if id != None:
            self.data = ImageDb.query.get(id)
        else:
            self.data = None

    def __getitem__(self, key):
        if self.data == None:
            return None
        return self.data.__getattribute__(key)

    def __setitem__(self, key, val):
        if self.data != None:
            self.data.__setattr__(key, val)

    def New(self, data):
        newImage = ImageDb(
                url = data['url'],
                owner = data['owner'],
                gender = data['gender'],
                tags = data['tags'],
                rank = 1000
        )
        db.session.add(newImage)
        db.session.commit()
        return 200, {"msg":"Success"}

    def GetImages(self, data):
        q = ImageDb.query.filter_by(gender = data['gender']).order_by(func.random()).limit(2)
        if q.count() != 2:
            return 400, {"msg":"没有符合条件的！"}
        images = q.all()
        return 200, {"images":[q[0].url, q[1].url]}
# ============================================================================
#                                 Server
# ============================================================================
# ----------------------------------
# ------ Utility Function ----------
# ----------------------------------
def GetResp(t):
    resp = flask.jsonify(t[1])
    resp.status_code = t[0]
    return resp
# ----------------------------------
#              API 
# ----------------------------------

@app.route('/login', methods=['POST'])
@require("username", "password", "remember")
def Login():
    data = request.get_json()
    u = User(username = data['username'], password = data['password'])
    return GetResp(u.Login(data["remember"]))

@app.route('/logoff', methods=['POST'])
@require("username", "token")
def Logoff():
    data = request.get_json()
    u = User(username = data['username'], token = data['token'])
    return GetResp(u.Logoff())

@app.route('/register', methods=['POST'])
@require("username", "password", "email")
def Register():
    data = request.get_json()
    u = User(data['username'])
    return GetResp(u.Register(data))

@app.route('/uservalid', methods=['POST'])
@require("username")
def ValidUser():
    data = request.get_json()
    if "token" in data:
        token = data["token"]
    else:
        token = None
    u = User(username = data['username'], token = token)
    if u.valid:
        resp = flask.jsonify({"valid":True})
        resp.status_code = 200
    else:
        resp = flask.jsonify({"valid":False})
        resp.status_code = 200
    return resp
@app.route('/signature', methods=['POST'])
def Signature():
    if CLOUDINARY_API_SECRET != None:
        data = request.get_json()
        for pickOutKey in ['file', 'type', 'resource_type', 'api_key']:
            if pickOutKey in data:
                data.pop(pickOutKey)
        s = '&'.join([str(t[0])+'='+str(t[1]) for t in sorted([(k, v) for k,v in data.items()])])
        s += CLOUDINARY_API_SECRET
        resp = flask.jsonify({"signature": hashlib.sha1(s).hexdigest()})
        resp.status_code = 200
    else:
        resp = flask.jsonify({"msg": "No valid cloudinary api secret exist"})
        resp.status_code = 403

    return resp
