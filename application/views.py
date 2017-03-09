from application import application, db
from flask import flash, redirect, render_template, request, session, url_for
from functools import wraps
from application.forms import RegisterForm, LoginForm
from application.models import User,Payment
from sqlalchemy.exc import IntegrityError
import os
import stripe
import jwt
import json
application.config.from_pyfile('keys.cfg')
stripe_keys = {
    'secret_key': application.config['SECRET_KEY'],
    'publishable_key': application.config['PUBLISHABLE_KEY']
}

stripe.api_key = stripe_keys['secret_key']

def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the %s field - %s" % (
                getattr(form, field).label.text,error), 'error')

def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return test(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))
    return wrap

@application.route('/logout/', methods=['GET', 'POST'])
def logout():
    session.pop('logged_in', None)
    session.pop('user_email', None)
    error = 'You are logged out'
    # redirect_to_index = render_template("login.html",                                       
    #                        form = LoginForm(request.form),                    
    #                        error = error) 
    redirect_to_index = redirect(url_for('login'))
    response = application.make_response(redirect_to_index)
    response.set_cookie('jwt', '', expires=0)
    # flash('You are logged out. Bye. :(')
    # return redirect (url_for('login'))
    return response  

@application.route('/')
@application.route('/', methods=['GET', 'POST'])
def login():
    error = None
    cookie_jwt = request.cookies.get("jwt")
    print "cookie_jwt", cookie_jwt
    if cookie_jwt is not None:
        try:                                                                   
            decoded = jwt.decode(cookie_jwt, 'fiveguys', algorithm='HS256')    
            print decoded                                                      
            print "here1?"                                                     
            redirect_to_index = render_template(("products.html"))             
            print "here2?"                                                     
            response = application.make_response(redirect_to_index)                    
            return response                                                    
        except:                                                                
            error = 'You have not logged in.'                                  
            return render_template("login.html",                                             
                            form = LoginForm(request.form),                    
                            error = error)  
    if request.method=='POST':
        u = User.query.filter_by(name=request.form['name'],
                          password=request.form['password']).first()
        if u is None:
            error = 'Invalid username or password.'
        else:
            session['logged_in'] = True
            session['user_email'] = u.email
            flash('You are logged in successfully.')
            payload = {}
            payload['name'] = u.name
            payload['email'] = u.email
            payload['password'] = u.password
            print payload
            print type(payload)
            context = dict(cid=u.id)
            # encoded = jwt.encode({'some': payload}, 'fiveguys', algorithm='HS256')
            encoded = jwt.encode({request.form['name']: request.form['password']}, 'fiveguys', algorithm='HS256')
            print encoded
            redirect_to_index = render_template(("products.html"), **context)
            response = application.make_response(redirect_to_index)
            response.set_cookie('jwt', value=encoded)
            return response

            # decode = jwt.decode(encoded, 'fiveguys', algorithms=['HS256'])
            # print decode
            #
            # return redirect(url_for('members'))


    return render_template("login.html",
                            form = LoginForm(request.form),
                            error = error)
@application.route('/order', methods=['GET', 'POST'])
def order():
    if (request.form.get('pay')):
      if not request.form.getlist('productlist'):
       error = "Please select the product!"
       contexts = dict(cid=request.form.get('pay'))
       return render_template("products.html", error=error, **contexts)
      else:
        global totalprice
        totalprice = 0
        cid=request.form.get('pay')
        value = request.form.getlist('productlist')
        ename=[]
        global price
        price = []
        for i in range(len(value)):
            totalprice=totalprice+float(value[i])
        print "totalprice",totalprice
        newcid=json.loads(cid)
        pay=Payment(newcid,totalprice)
        db.session.add(pay)
        db.session.commit()
        payments=Payment.query.all()
        print payments
        context = dict(totalprice=totalprice)
        return render_template("members.html", key=stripe_keys['publishable_key'],**context)

@application.route('/products/')
@login_required
def products():
    return render_template('products.html')
@application.route('/members/')
@login_required
def members():
    return render_template('members.html', key=stripe_keys['publishable_key'])
@login_required
@application.route('/charge', methods=['GET','POST'])
def charge():
    # Amount in cent
    amount = int(totalprice*100)

    email = session['user_email']

    customer = stripe.Customer.create(
        email=email,
        card=request.form['stripeToken']
    )

    charge = stripe.Charge.create(
        customer=customer.id,
        amount=amount,
        currency='usd',
        description='Flask Charge'
    )
    context=dict(totalprice=amount)
    return render_template('charge.html', amount=amount,**context)

@application.route('/register/', methods=['GET','POST'])
def register():
    error = None
    form = RegisterForm(request.form, csrf_enabled=False)
    if form.validate_on_submit():
        new_user = User(
                    form.name.data,
                    form.email.data,
                    form.password.data,
                    )
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Thanks for registering. Please login.')
            return redirect(url_for('login'))
        except IntegrityError:
            error = 'That username and/or email already exist. Please try again.'
    else:
        flash_errors(form)
    return render_template('register.html', form=form, error=error)

@application.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@application.errorhandler(404)
def internal_error(error):
    return render_template('404.html'), 404
