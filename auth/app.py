from flask import Flask, abort, request, render_template, url_for
from flask_security import Security, login_required, current_user, utils, \
     SQLAlchemySessionUserDatastore
     
from flask_admin import Admin
from flask_admin import helpers as admin_helpers

from database import db_session, init_db
from models import User, Role 
from admin_views import UserAdmin, RoleAdmin

import os
import re
import requests


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
    
    Gets a GET request without body for every request to the resource.
    Returns 2xx for access granted and 4xx for access denied.
    """
    #app.logger.debug('headers: %s'%request.headers)
    uri = request.headers.get('Original-Uri')
    if current_user.is_authenticated:
        app.logger.debug("query_auth OK for %s"%uri)
        return 'OK'
    else:
        app.logger.debug("query_auth FAIL for %s"%uri)
        abort(403)

# IIIF auth cookie endpoint
@app.route('/iiif_login')
@login_required
def iiif_login():
    """
    Endpoint used by IIIF cookie service.

    see https://iiif.io/api/auth/1.0/#access-cookie-service
    """
    app.logger.debug('iiif_login!')
    app.logger.debug('headers: %s'%request.headers)
    #uri = request.headers.get('Original-Uri')
    
    # context for flask-admin page template
    return render_template('iiif-login.html',         
                           admin_base_template=admin.base_template,
                           admin_view=admin.index_view,
                           h=admin_helpers,
                           get_url=url_for)


# IIIF auth logout endpoint
@app.route('/iiif_logout')
def iiif_logout():
    app.logger.debug('iiif_logout!')
    app.logger.debug('headers: %s'%request.headers)
    utils.logout_user()
    return 'User logged out!'

# IIIF auth cookie endpoint
@app.route('/iiif_token')
def iiif_token():
    app.logger.debug('iiif_token!')
    app.logger.debug('headers: %s'%request.headers)
    return 'Sorry, not implemented.'

# IIIF info.json proxy endpoint
@app.route('/iiif_info_proxy')
def iiif_info_proxy():
    app.logger.debug('iiif_info_proxy!')
    app.logger.debug('headers: %s'%request.headers)
    uri = request.headers.get('Original-Uri')
    app.logger.debug("uri: %s"%uri)
    iiif_match = re.search(r'([^/]+/info.json)', uri)
    if iiif_match is None:
        return abort(404)
    
    iiif_param = iiif_match.group(1)
    info_url = "http://proxy/iiif-internal/%s"%iiif_param
    app.logger.debug("info_url: %s"%info_url)
    resp = requests.get(info_url)
    app.logger.debug("reason: %s"%resp.reason)
    if resp.ok:
        info_json = resp.json()
        app.logger.debug("info: %s"%info_json)
        return resp.content
    else:
        return abort(500)



# magic to mount app with prefix when run locally
# def simple(env, resp):
#     resp(b'200 OK', [(b'Content-Type', b'text/plain')])
#     return [b'Hello WSGI World']
# 
# app.wsgi_app = DispatcherMiddleware(simple, {'/auth': app.wsgi_app})

if __name__ == '__main__':
    app.run()
