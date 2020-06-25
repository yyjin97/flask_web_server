from flask import Flask, g, request, Response, make_response
from flask import session, render_template, Markup,redirect, url_for,escape, flash
from datetime import date, datetime, timedelta
from dateutil.relativedelta import relativedelta

app = Flask(__name__)
app.debug = True

from _SB_web import mongodb

app.config.update(
    SECRET_KEY = "SmArTbUlDiNg43ufr8eh9",
    SESSION_COOKIE_NAME="pyweb_session",
    PERMANENT_SESSION_LIFETIME=timedelta(31)        #31days
) 

@app.route('/', methods=['POST','GET'])
def idx():
    # today = date.today()
    # today = datetime.now()
    name = ''
    today = datetime.now()
    if 'user_id' in session:
        name = {"f_name":'', "l_name":''}
        user_id = escape(session['user_id'])
        name['f_name'], name['l_name'] = mongodb.get_name_with_id(user_id)
    return render_template('app.html', name=name, main_page=True)

@app.route('/logout')
def logout():
    if session.get('user_id'):
        del session['user_id']
        flash("Successfully Logout")
        return redirect(url_for('idx'))
    return redirect(url_for('idx'))

@app.route('/resetpw')
def resetpw():
    name = ''
    if 'user_id' in session:
        name = { 'f_name':'', 'l_name':'' }
        user_id = escape(session['user_id'])
        name['f_name'], name['l_name'] = mongodb.get_name_with_id(user_id)
    return render_template('resetpw.html', name=name)