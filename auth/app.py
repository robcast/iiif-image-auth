from flask import Flask, abort, request, render_template, url_for, \
    json, jsonify
from flask_security import Security, login_required, current_user, utils, \
     SQLAlchemySessionUserDatastore
     
from flask_admin import Admin
from flask_admin import helpers as admin_helpers

from itsdangerous import JSONWebSignatureSerializer

from database import db_session, init_db
from models import User, Role 
from admin_views import UserAdmin, RoleAdmin

import os, time

# token lifetime in seconds
TOKEN_LIFETIME = os.environ.get('TOKEN_LIFETIME', 3600)
TOKEN_AUDIENCE = os.environ.get('TOKEN_AUDIENCE', 'ISMI-Images')

# Create app
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SECURITY_PASSWORD_SALT'] = os.environ['SECURITY_PASSWORD_SALT']
#app.config['SECURITY_URL_PREFIX'] = "/auth"
app.config['SECURITY_POST_LOGIN_VIEW'] = "/auth/"
app.config['SECURITY_POST_LOGOUT_VIEW'] = "/auth/"
app.config['SECURITY_TRACKABLE'] = False

# Initialize Flask-Security
user_datastore = SQLAlchemySessionUserDatastore(db_session, User, Role)
security = Security(app, user_datastore)

# Initialize Flask-Admin
admin = Admin(app, name='ISMI image server authentication', template_mode='bootstrap3')
# set brand link url for main template
#admin.index_view.admin.url = '/auth/admin'

# Add Flask-Admin views for Users and Roles
admin.add_view(UserAdmin(User, db_session))
admin.add_view(RoleAdmin(Role, db_session))

# define a context processor for merging flask-admin's template context into the
# flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
        get_url=url_for
    )

# Setup database and create admin user
@app.before_first_request
def before_first_request():
    init_db()
    # create admin user if it doesn't exist
    if not user_datastore.get_user(os.environ['ADMIN_USERID']):
        user_datastore.create_user(email=os.environ['ADMIN_USERID'], password=os.environ['ADMIN_PASSWORD'])
        
    # Create the Roles "admin" and "user"
    user_datastore.find_or_create_role(name='admin', description='Administrator')
    user_datastore.find_or_create_role(name='user', description='User')
    # commit before we use roles and users
    db_session.commit()
    # add admin role to admin user
    user_datastore.add_role_to_user(os.environ['ADMIN_USERID'], 'admin')
    db_session.commit()


##
## views
##

@app.route('/')
def index():
    # context for flask-admin page template
    return render_template('index.html',         
                           admin_base_template=admin.base_template,
                           admin_view=admin.index_view,
                           h=admin_helpers,
                           get_url=url_for)

# nginx auth endpoint
@app.route('/query_auth', methods=['GET'])
def validate():
    """
    Endpoint used by nginx auth_request.
    Uses Flask session or token in "Authorization" header.
    
    Gets a GET request without body for every request to the resource.
    Returns 2xx for access granted and 4xx for access denied.
    """
    app.logger.debug('validate headers: %s'%request.headers)
    uri = request.headers.get('Original-Uri')
    if current_user.is_authenticated:
        app.logger.debug("query_auth OK for %s"%uri)
        return 'OK'
    
    auth_header = request.headers.get('Authorization')
    if auth_header:
        signer = JSONWebSignatureSerializer(os.environ['SECRET_KEY'])
        try:
            jwt_token = auth_header.replace('Bearer ', '', 1)
            token = signer.loads(jwt_token)
            app.logger.debug("validate token: %s"%repr(token))
            audience = token['aud']
            exp_time = token['exp']
            curr_time = int(time.time())
            if curr_time <= exp_time and audience == TOKEN_AUDIENCE:
                app.logger.debug("query_auth OK for %s"%uri)
                return 'OK'
            
        except:
            app.logger.debug("Unable to validate auth token: %s"%auth_header)
            
    app.logger.debug("query_auth FAIL for %s"%uri)
    abort(401)

# IIIF auth cookie endpoint
@app.route('/iiif-login')
@login_required
def iiif_login():
    """
    Endpoint used by IIIF cookie service. 
    Accessed in normal browser context with cookies.
    Presents user login form, creates session cookie and closes the window.

    @see https://iiif.io/api/auth/1.0/#access-cookie-service
    """
    app.logger.debug('iiif_login!')
    app.logger.debug('headers: %s'%request.headers)
    #uri = request.headers.get('Original-Uri')
    # TODO: get origin parameter (and then?) 
    # context for flask-admin page template
    return render_template('iiif-login.html',         
                           admin_base_template=admin.base_template,
                           admin_view=admin.index_view,
                           h=admin_helpers,
                           get_url=url_for)

# IIIF auth token endpoint
@app.route('/iiif-token')
def iiif_token():
    """
    Endpoint used by IIIF token service.
    Accessed in normal browser context with cookies.
    Returns page with Javascript PostMessage with token for browser-based clients
    (if messageId parameter is set).
    Returns JSON with token for other clients.

    @see https://iiif.io/api/auth/1.0/#access-token-service
    """
    app.logger.debug('iiif_token!')
    app.logger.debug('headers: %s'%request.headers)
    uri = request.headers.get('Original-Uri')
    origin_url = request.args.get('origin')
    message_id = request.args.get('messageId')
    
    if current_user.is_authenticated:
        app.logger.debug("token auth OK")
        # create token
        curr_utime = int(time.time())
        exp_utime = curr_utime + TOKEN_LIFETIME
        token_payload = {
            'sub': current_user.email,
            'aud': TOKEN_AUDIENCE,
            'iat': curr_utime,
            'exp': exp_utime
        }
        signer = JSONWebSignatureSerializer(os.environ['SECRET_KEY'])
        token = signer.dumps(token_payload).decode()
        json_payload = {
            'accessToken': token,
            'expiresIn': TOKEN_LIFETIME
        }
        if message_id:
            # return postmessage html
            json_payload["messageId"] = message_id
            return render_template('iiif-token.html', 
                                   json_payload=json.dumps(json_payload),
                                   origin_url=origin_url)
        
        else:
            return jsonify(json_payload)
        
    else:
        app.logger.debug("token auth FAIL")
        json_payload = {
            'error': 'invalidCredentials',
            'description': 'Missing or invalid credentials!'
        }
        if message_id:
            # return postmessage html
            json_payload["messageId"] = message_id
            return render_template('iiif-token.html', 
                                   json_payload=json.dumps(json_payload),
                                   origin_url=origin_url)
        
        else:
            return jsonify(json_payload), 403


# magic to mount app with prefix when run locally
# def simple(env, resp):
#     resp(b'200 OK', [(b'Content-Type', b'text/plain')])
#     return [b'Hello WSGI World']
# 
# app.wsgi_app = DispatcherMiddleware(simple, {'/auth': app.wsgi_app})

if __name__ == '__main__':
    app.run()
