from flask import Flask, abort, request
from flask_security import Security, login_required, current_user, \
     SQLAlchemySessionUserDatastore
from database import db_session, init_db
from models import User, Role
from werkzeug.wsgi import DispatcherMiddleware
import os

# Create app
app = Flask(__name__)
#app.config["APPLICATION_ROOT"] = '/auth'
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = os.environ['APP_SECRET_KEY']
app.config['SECURITY_PASSWORD_SALT'] = os.environ['SECURITY_PASSWORD_SALT']

# Setup Flask-Security
user_datastore = SQLAlchemySessionUserDatastore(db_session,
                                                User, Role)
security = Security(app, user_datastore)

# Create a user to test with
@app.before_first_request
def create_user():
    init_db()
    user_datastore.create_user(email='matt@nobien.net', password='password')
    db_session.commit()

# Views
@app.route('/')
@login_required
def home():
    return 'You are logged in!'

@app.route('/hello')
def hello():
    return 'Hello!'

# Views
@app.route('/query_auth', methods=['GET'])
def validate():
    uri = request.headers.get('x-original-uri')
    app.logger.error('original uri: %s'%uri)
    sc = request.cookies.get('session')
    app.logger.error('session cookie: %s'%sc)
    if current_user.is_authenticated:
        return 'validate OK'
    else:
        abort(403)

# magic to mount app with prefix
def simple(env, resp):
    resp(b'200 OK', [(b'Content-Type', b'text/plain')])
    return [b'Hello WSGI World']

app.wsgi_app = DispatcherMiddleware(simple, {'/auth': app.wsgi_app})

if __name__ == '__main__':
    app.run()
