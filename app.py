# coding=utf-8
# python built-in libs
import os
import time
import base64
import hashlib
import json
import functools
import urllib
import random

# SQL stuff
import psycopg2

# Flask
import flask
from flask import Flask, request, render_template
from flask_login import LoginManager
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message

# Cloudinary
import cloudinary.api

# Initialization
if os.environ.get('DATABASE_URL') != None:
    DATABASE_URL = os.environ.get('DATABASE_URL')
else:
    DATABASE_URL = "postgresql+psycopg2://gaotian:password@localhost:5432/yanrank"
CLOUDINARY_API_SECRET = os.environ.get('CLOUDINARY_API_SECRET')
cloudinary.config( 
    cloud_name = "yanrank", 
    api_key = "585812587869167",
    api_secret = CLOUDINARY_API_SECRET
)
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
CORS(app)
db = SQLAlchemy(app)

# ============================================================================
#                            Table like data 
# ============================================================================
availableTags = ["UCSB", "Cornell", "明星", "素人", "学生", "测试"]

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
    total_choice  = db.Column(db.Integer, default=0)
    good_judge    = db.Column(db.Integer, default=0)
    bad_judge     = db.Column(db.Integer, default=0)
    credit        = db.Column(db.Integer, default=0)
    money         = db.Column(db.Integer, default=0)

class ImageDb(db.Model):
    __tablename__ = 'images'
    id            = db.Column(db.Integer, primary_key=True)
    url           = db.Column(db.Text, default="")
    gender        = db.Column(db.String(2), default="f")
    tags          = db.Column(db.Text, default="")
    rank          = db.Column(db.Integer, default=1000)
    rank_time     = db.Column(db.Integer, default=0)
    owner         = db.Column(db.String(50), default="")

class TagDb(db.Model):
    __tablename__ = 'tags'
    id            = db.Column(db.Integer, primary_key = True)
    key           = db.Column(db.String(32))
    name          = db.Column(db.String(32), default="")
    owner         = db.Column(db.String(50))

class ReportDb(db.Model):
    __tablename__ = 'reports'
    id            = db.Column(db.Integer, primary_key = True)
    type          = db.Column(db.String(32))
    url           = db.Column(db.Text, default="")
    note          = db.Column(db.Text, default="")

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

    def GetInfo(self, data):
        if self.valid:
            ret = {}
            ret['total'] = self['total_choice']
            ret['point'] = self['good_judge']*100.0 / max(1, (self['bad_judge'] + self['good_judge']))
            ret['images'] = []
            ret['tags'] = []
            if self['username'] == 'admin':
                q = ImageDb.query
            else:
                q = ImageDb.query.filter_by(owner = self['username'])
            images = q.all()
            for im in images:
                i = Image(data = im)
                ret['images'].append(i.GetInfo())
            q = TagDb.query.filter_by(owner = self['username'])
            tags = q.all()
            for tag in tags:
                t = Tag(data = tag)
                ret['tags'].append(t.GetInfo())
            return 200, ret
        return 400, {"msg": "user not valid"}


class Image:
    def __init__(self, id = None, url = None, data = None):
        self.valid = False
        if id != None:
            self.data = ImageDb.query.get(id)
            if self.data != None:
                self.valid = True
        elif url != None:
            self.data = ImageDb.query.filter_by(url = url).first()
            if self.data != None:
                self.valid = True
        elif data != None:
            self.data = data
            self.valid = True
        else:
            self.data = None

    def __getitem__(self, key):
        if self.data == None:
            return None
        if key == 'tags':
            return self.data.tags.split('\n')
        else:
            return self.data.__getattribute__(key)

    def __setitem__(self, key, val):
        if self.data != None:
            if key == 'tags':
                self.data.__setattr__(key, '\n'.join(val))
            else:
                self.data.__setattr__(key, val)

    def New(self, data):
        for url in data['urlList']:
            newImage = ImageDb(
                    url = url,
                    owner = data['owner'],
                    gender = data['gender'],
                    tags = '\n'.join(data['tags']),
                    rank = 1000
            )
            db.session.add(newImage)
        db.session.commit()
        return 200, {"msg":"Success"}

    def RemoveTag(self, tag):
        tempList = self['tags'][:]
        tempList.remove(tag)
        self['tags'] = tempList
        db.session.commit()

    def DeleteImage(self, username = "", urlList=None):
        if self.valid:
            public_id = self['url'].split('/')[-1].split('.')[0]
            ret = cloudinary.api.delete_resources(public_ids = [public_id])
            db.session.delete(self.data)
            db.session.commit()
            return 200, {"msg": "Success"}
        elif urlList != None:
            for url in urlList:
                if username == "admin":
                    im = ImageDb.query.filter_by(url = url).first()
                else:
                    im = ImageDb.query.filter_by(url = url, owner = username).first()
                if im != None:
                    public_ids = url.split('/')[-1].split('.')[0] 
                    db.session.delete(im)
            db.session.commit()
            ret = cloudinary.api.delete_resources(public_ids = public_ids)
            return 200, {"msg": "Success"}
        return 400, {"msg": "Image invalid"}

    def EditImage(self, data):
        if self.valid:
            if self['owner'] == data['username'] or data['username'] == "admin":
                self['gender'] = data['gender']
                self['tags'] = data['tags']
                db.session.commit()
                return 200, {"msg": "Success!"}
            return 401, {"msg": "Invalid User!"}
        return 400, {"msg": "Invalid image"}

    def GetImages(self, data):
        if data['gender'] == '':
            data['gender'] = random.choice(['m', 'f'])
        q = ImageDb.query.filter(ImageDb.gender == data['gender'], ImageDb.tags.like('%'+data['tag']+'%')).order_by(db.func.random()).limit(data['number'])
        if q.count() != data['number']:
            return 400, {"msg":"此类别没有足够多的照片！"}
        images = q.all()
        urlList = []
        for im in images:
            urlList.append(im.url)
        return 200, {"images":urlList}

    def GetRanking(self, data):
        q = ImageDb.query.filter(ImageDb.gender == data['gender'], ImageDb.tags.like('%'+data['tag']+'%')).order_by(ImageDb.rank.desc()).limit(data['number'])
        images = q.all()
        urlList = []
        for im in images:
            urlList.append(im.url)
        return 200, {"ranking":urlList}

    def GetInfo(self):
        if self.valid:
            ret = {}
            ret['url'] = self['url']
            ret['tags'] = self['tags']
            ret['gender'] = self['gender']
            if self['rank_time'] < 10:
                ret['rank'] = u'评估中'
            else:
                ret['rank'] = self['rank']
            return ret
        return None

    def PickImage(self, data):
        qWin = ImageDb.query.filter_by(url = data['win'])
        qLose = ImageDb.query.filter_by(url = data['lose'])
        winIm = qWin.first()
        loseIm = qLose.first()
        if winIm != None and loseIm != None:
            if winIm.rank_time < 10:
                kwin = 40
            else:
                kwin = 10
            if loseIm.rank_time < 10:
                klose = 40
            else:
                klose = 10
            winScore = winIm.rank
            loseScore = loseIm.rank
            ewin = 1.0/(1+10.0**((loseScore - winScore)/400.0))
            elose = 1.0/(1+10.0**((winScore - loseScore)/400.0))
            winIm.rank = winIm.rank + kwin*(1.0 - ewin)
            loseIm.rank = loseIm.rank + klose*(0.0 - elose)
            winIm.rank_time = winIm.rank_time + 1
            loseIm.rank_time = loseIm.rank_time + 1
            db.session.commit()
            goodJudge = 0
            badJudge = 0
            if winIm.rank_time < 10 or loseIm.rank_time < 10:
                msg = "还在评估中，我也不知道你选的对不对"
                judge = "normal"
            elif winIm.rank - loseIm.rank > 100:
                msg = "这么明显，是个人都看的出来"
                judge = "correct"
                goodJudge = 1
            elif winIm.rank - loseIm.rank > 50:
                msg = "恩，审美还算过关，不错哦！"
                judge = "correct"
                goodJudge = 3
            elif winIm.rank - loseIm.rank > 20:
                msg = "你选的人也就是稍胜一筹，勉强算你对吧"
                judge = "correct"
                goodJudge = 2
            elif winIm.rank - loseIm.rank > -20:
                msg = "这俩人差不多，选谁都算不上错。"
                judge = "normal"
            elif winIm.rank - loseIm.rank > -50:
                msg = "你选的人稍逊一筹，有点可惜，不要太难过"
                judge = "wrong"
                badJudge = 1
            elif winIm.rank - loseIm.rank > -100:
                msg = "你这审美有点着急啊，赶紧回家练练吧"
                judge = "wrong"
                badJudge = 2
            else:
                msg = "你是不是眼神有问题？回去配副眼镜好不好？"
                judge = "wrong"
                badJudge = 3
            if data['user'] != '':
                u = User(data['user'])
                if u.valid:
                    u['good_judge'] += goodJudge
                    u['bad_judge'] += badJudge
                    u['total_choice'] += 1
                    db.session.commit()
            return 200, {"msg":msg, "judge":judge, "good_judge":goodJudge, "bad_judge": badJudge}
        return 400, {"msg":"数据库有问题"}

class Tag:
    def __init__(self, key = None, data = None):
        self.valid = False
        if key != None:
            self.data = TagDb.query.filter_by(key = key).first()
            if self.data != None:
                self.valid = True
        elif data != None:
            self.data = data
            self.valid = True
        else:
            self.data = None

    def __getitem__(self, key):
        if self.data == None:
            return None
        return self.data.__getattribute__(key)

    def __setitem__(self, key, val):
        if self.data != None:
            self.data.__setattr__(key, val)

    def GetInfo(self):
        ret = {}
        if self.valid:
            ret['name'] = self['name']
            ret['key'] = self['key']
        return ret

    def CreateTag(self, data):
        key = base64.urlsafe_b64encode(os.urandom(12))
        while TagDb.query.filter_by(key = key).first() != None:
            key = base64.urlsafe_b64encode(os.urandom(12))

        newTag = TagDb(
                key = key,
                name = data['name'],
                owner = data['username']
        )
        db.session.add(newTag)
        db.session.commit()
        return 200, {"key": key}

    def DeleteTag(self, data):
        if self.valid == True:
            if self['owner'] == data['username']:
                images = ImageDb.query.filter(ImageDb.tags.like('%'+self['key']+'%')).all()
                for imdata in images:
                    im = Image(data = imdata)
                    im.RemoveTag(self['key'])
                db.session.delete(self.data)
                db.session.commit()
                return 200, {"msg": "Success"}
            return 401, {"msg": "User is not the owner!"}
        return 400, {"msg": "There is not such tag!"}

    def CheckTag(self):
        if self.valid == True:
            return 200, {"name": self['name']}
        return 400, {"msg": "No such tag."}

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

@app.route('/userinfo', methods=['POST'])
@require("username", "token")
def UserInfo():
    data = request.get_json()
    u = User(username = data['username'], token = data['token'])
    return GetResp(u.GetInfo(data))

@app.route('/addimage', methods=['POST'])
@require("urlList", "owner", "gender", "tags")
def AddImage():
    data = request.get_json()
    im = Image()
    return GetResp(im.New(data))

@app.route('/getimages', methods=['POST'])
@require('gender', 'tag', 'number')
def GetImages():
    data = request.get_json()
    im = Image()
    return GetResp(im.GetImages(data))

@app.route('/cancelimage', methods=['POST'])
@require('username', 'token', 'urlList')
def CancelImage():
    data = request.get_json()
    u = User(username = data['username'], token = data['token'])
    if u.valid:
        im = Image()
        return GetResp(im.DeleteImage(username = u['username'], urlList = data['urlList']))
    else:
        return GetResp(im.DeleteImage(username = '', urlList = data['urlList']))


@app.route('/deleteimage', methods=['POST'])
@require('username', 'token', 'urlList')
def DeleteImage():
    data = request.get_json()
    u = User(username = data['username'], token = data['token'])
    if u.valid:
        im = Image()
        return GetResp(im.DeleteImage(username = u['username'], urlList = data['urlList']))
    else:
        return GetResp((401, {"msg": "User not valid"}))

@app.route('/editimage', methods=['POST'])
@require('username', 'token', 'url', 'gender', 'tags')
def EditImage():
    data = request.get_json()
    u = User(username = data['username'], token = data['token'])
    if u.valid:
        im = Image(url = data['url'])
        return GetResp(im.EditImage(data))
    else:
        return GetResp((401, {"msg":"User not log in!"}))

@app.route('/getranking', methods=['POST'])
@require('gender', 'tag', 'number')
def GetRanking():
    data = request.get_json()
    im = Image()
    return GetResp(im.GetRanking(data))

@app.route('/pickimage', methods=['POST'])
@require('user', 'win', 'lose')
def PickImage():
    data = request.get_json()
    im = Image()
    return GetResp(im.PickImage(data))

@app.route('/createtag', methods=['POST'])
@require('username', 'token', 'name')
def CreateTag():
    data = request.get_json()
    u = User(username = data['username'], token = data['token'])
    if u.valid:
        tag = Tag()
        return GetResp(tag.CreateTag(data))
    else:
        return GetResp((401, {"msg":"User not log in!"}))

@app.route('/deletetag', methods=['POST'])
@require('username', 'token', 'key')
def DeleteTag():
    data = request.get_json()
    u = User(username = data['username'], token = data['token'])
    if u.valid:
        tag = Tag(key = data['key'])
        if tag.valid:
            return GetResp(tag.DeleteTag(data))
        else:
            return GetResp((400, {"msg":"Wrong tag!"}))
    else:
        return GetResp((401, {"msg":"Invalid user!"}))

@app.route('/checktag', methods=['POST'])
@require('key')
def CheckTag():
    data = request.get_json()
    tag = Tag(key = data['key'])
    if tag.valid:
        return GetResp(tag.CheckTag())
    else:
        return GetResp((400, {"msg":"Wrong tag!"}))

@app.route('/getavailabletags', methods=['POST'])
def GetAvailabelTags():
    return GetResp((200, availableTags))

@app.route('/signature', methods=['POST'])
def Signature():
    if CLOUDINARY_API_SECRET != None:
        data = request.get_json()
        for pickOutKey in ['file', 'type', 'resource_type', 'api_key']:
            if pickOutKey in data:
                data.pop(pickOutKey)
        s = '&'.join([str(t[0])+'='+str(t[1]) for t in sorted([(k, v) for k,v in data.items()])])
        s = s.replace('=True', '=true')
        s += CLOUDINARY_API_SECRET
        resp = flask.jsonify({"signature": hashlib.sha1(s).hexdigest()})
        resp.status_code = 200
    else:
        resp = flask.jsonify({"msg": "No valid cloudinary api secret exist"})
        resp.status_code = 403

    return resp
