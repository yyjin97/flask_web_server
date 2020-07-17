from flask import Flask, request, session, redirect, url_for, flash, render_template, jsonify
from flask import make_response
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from pymongo import MongoClient, encryption
from hashlib import sha512
import bcrypt, json, jwt, time, socket
from bson import json_util

from _SB_web import app

client = MongoClient("mongodb://127.0.0.1:27017/")
db = client["pyweb"]
collection = db["users"]

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'ncwebflask@gmail.com'
app.config['MAIL_PASSWORD'] = 'abc_12345'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

app.config['JWT_SECRET_KEY'] = 'SmartBuilding scretkey!'
   
@app.route('/reset_form/<token>', methods=['POST','GET'])
def reset_form(token):
    try:
        id = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])['user_id']
    except Exception as e:
        return render_template("base.html", content="Page Timeout !")
    user = request.cookies.get('resetEmail')
    if((not user) or (user != id)):
        flash("Access denied !")
        return redirect(url_for('idx'))
    return render_template("email/reset_window.html", ShowNotMatch=False)

@app.route('/resetpwdb', methods=['POST','GET'])
def resetpwdb():
    if(request.method == 'POST'):
        pw1 = request.form['password_1']
        pw2 = request.form['password_2']
        if(pw1 != pw2):
            return render_template("email/reset_window.html", ShowNotMatch=True)
        
        user_id = request.cookies.get('resetEmail')
        if(not user_id):
            return render_template("base.html", content="Page Timeout!")

        user_pw = bcrypt.hashpw(request.form['password_1'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        collection.update_one({"user_id":user_id}, {"$set":{"user_pw":user_pw}})

        flash("Password reset complete :)")
        return redirect(url_for('idx'))
    flash("Invalid method !")
    return redirect(url_for('idx'))

def get_ipaddress():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("gmail.com",80))
  r = s.getsockname()[0]
  s.close()
  return r

def send_mail(title, sender, receiver): 
    msg = Message(title, sender=sender)
    token = jwt.encode( {'user_id':receiver, 'exp':time.time()+300}, app.config['JWT_SECRET_KEY'], algorithm='HS256')
    f_name, l_name = get_name_with_id(receiver)
    host = str(get_ipaddress()) + ":5000/" + str(token)
    msg_body = render_template('email/reset_email_form.html', token=token, _external=True, host=host, f_name=f_name, l_name=l_name)
    msg.add_recipient(receiver)
    msg.html = msg_body
    mail.send(msg)
    return

def get_name_with_id(user_id):
    user = list(collection.find({"user_id":user_id}))
    if(user != []):
        return user[0]['name']['first_name'], user[0]['name']['last_name']
    return Null

def web_login(request):    
    if(request.method == 'POST'):
        user_id = request.form['user_id']
        user_pw = request.form['user_pw'].encode('utf-8')
        if(user_id == '' or user_pw == ''):
            flash("Enter ID and password !")
            return user_id
        user = list(collection.find({"user_id":user_id }))
        if(user != []):
            if(bcrypt.checkpw(user_pw, user[0]['user_pw'].encode('utf-8'))):
                session['user_id'] = user_id
                flash("Welcome %s" % user_id)
            else:
                flash("Login Fail : Invalid password !")
        else:
            flash("Login Fail : Invalid Id !") 
        return user_id
    else:
        flash("Invalid method !")
        return 

def app_login(user):
    if(request.method == 'POST'):
        user_id = user['user_id']
        user_pw = user['user_pw']
        if(user_id == '' or user_pw == ''):
            flash("Enter ID and password !")
            return "fail"
        user = list(collection.find({"user_id":user_id }))
        if(user != []):
            if(bcrypt.checkpw(user_pw, user[0]['user_pw'].encode('utf-8'))):
                session['user_id'] = user_id
                return "success"
            else:
                return "fail"
        else:
            return "fail" 
    else:
        return "fail"

@app.route('/login', methods=['POST','GET'])
def login():
    if(request.json is None):
        user_id = web_login(request)
        if(not user_id):
            return redirect(url_for('idx'))
        res = make_response(redirect(url_for('idx')))
        isRemember = request.form.get('IsRemember')
        if(isRemember):
            res.set_cookie('RememberEmail', value=user_id, max_age=60*60*24*10)
        else:
            res.set_cookie('RememberEmail', expires=0)
        res.set_cookie('userID', value=user_id, max_age=60*60*24)
        return res
    else:
        user = request.get_json()
        return app_login(user)

@app.route('/register', methods=['POST','GET'])
def register():
    if(request.method == 'POST'):
        phone_num = request.form['phone_num']
        user_id = request.form['user_id']
        first_name = request.form['first_name']
        last_name = request.form['last_name']

        user_pw = bcrypt.hashpw(request.form['user_pw'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        if(user_id == '' or user_pw == '' or first_name == '' or last_name == ''):
            flash("Please fill in all the blacks (except phone number)")
            return redirect(url_for('idx'))
        check = list(collection.find({"user_id":user_id}))
        if(check != []):
            flash("Already existing ID !")
        else:
            collection.insert({"user_id":user_id, "user_pw":user_pw, "name":{ "first_name":first_name, "last_name":last_name }, "phone_num":phone_num})
            flash("Successfully register :)")
    else:
        flash("Register Fail !")
    return redirect(url_for('idx'))


@app.route('/sendemail', methods=['POST','GET'])
def sendemail():
    if(request.method == 'POST'):
        email = request.form['email']

        col = list(collection.find({"user_id":email}))
        if(col != []):
            send_mail("Reset password", app.config.get('MAIL_USERNAME'), email)
            res = make_response(render_template("base.html", content="Password reset email has been sent :)"))
            res.set_cookie('resetEmail', value=email, max_age=600)
            return res
        else:
            flash("Invalid Id! Please enter another ID")
            return redirect(url_for('resetpw'))
    flash("Invalid method !")
    return redirect(url_for('idx'))

    
