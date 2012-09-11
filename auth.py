# -*- coding: utf-8 -*-
from flask import Flask, redirect, url_for, flash, render_template, g, current_app, request

#from werkzeug.security import generate_password_hash, check_password_hash

from flask.ext.wtf import Form, TextField, PasswordField, SubmitField, validators, Required, Email, CheckboxInput
from flask.ext.sqlalchemy import SQLAlchemy

# AUTH
from flask.ext.sqlalchemy import BaseQuery
from flask.ext.principal import Principal, RoleNeed, UserNeed, Permission, Identity, identity_changed, identity_loaded, AnonymousIdentity
from werkzeug.utils import cached_property

app = Flask(__name__)
app.config.update(
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test.sqlite',
    DEBUG = True,
    SECRET_KEY = 'secret'
)

db = SQLAlchemy(app)

Principal(app)

# User Information providers
@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    g.user = User.query.from_identity(identity)

# Permission
admin = Permission(RoleNeed('admin'))
member = Permission(RoleNeed('member'))

# MODELS
class UserQuery(BaseQuery):

    def from_identity(self, identity):
        """
        Loads user from flask.ext.principal.Identity instance and
        assigns permissions from user.

        A "user" instance is monkeypatched to the identity instance.

        If no user found then None is returned.
        """

        try:
            user = self.get(int(identity.name))
        except ValueError:
            user = None

        if user:
            identity.provides.update(user.provides)

        identity.user = user

        return user

class User(db.Model):

    query_class = UserQuery

    MEMBER = 100
    ADMIN = 300

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80))
    role = db.Column(db.Integer, default=100)

    @cached_property
    def permissions(self):
        return self.Permissions(self)

    @cached_property
    def provides(self):
        needs = [RoleNeed('authenticated'), UserNeed(self.id)]

        if self.is_member:
            needs.append(RoleNeed('member'))

        if self.is_admin:
            needs.append(RoleNeed('admin'))

        return needs

    @property
    def is_member(self):
        return self.role == self.MEMBER

    @property
    def is_admin(self):
        return self.role == self.ADMIN

# FORMS
class SignupForm(Form):
    username = TextField("Username", [validators.Required(message="Can't be blank!")])
    password = PasswordField("Password", [validators.Required(message="Can't be blank!")])
    submit = SubmitField("Signup")

class LoginForm(Form):
    username = TextField("Username", [validators.Required(message="Can't be blank!")])
    password = PasswordField("Password", [validators.Required(message="Can't be blank!")])
    submit = SubmitField("Login")

# VIEWS
@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/signup', methods=('GET', 'POST'))
def signup():

    form = SignupForm()

    if form.validate_on_submit():
        user = User()
        form.populate_obj(user)

        db.session.add(user)
        db.session.commit()

        flash('Signup Success %s' % user.username, 'success')

        return redirect(url_for('index'))

    return render_template('signup.html', form=form)

@app.route('/login', methods=('GET', 'POST',))
def login():

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter(User.username==form.username.data).first()
        if user:
            if user.password != form.password.data:
                flash(u'密码不匹配!')

            identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))

            flash(u'欢迎你, %s' % user.username)

            return redirect(url_for('index'))
        else:
            flash(u'用户不存在!')

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    identity_changed.send(current_app._get_current_object(), identity=AnonymousIdentity())
    flash(u'登出成功!')

    return redirect(url_for('index'))

@app.route('/page')
@admin.require(401)
def page():
    return render_template('page.html')

@app.errorhandler(401)
def unauthorized(error):
    flash('Please login to see this page', 'error')
    return redirect(url_for('login', next=request.path))

if __name__ == '__main__':
    app.run()