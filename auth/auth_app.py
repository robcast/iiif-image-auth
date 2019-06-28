from flask import Flask, abort, request, render_template, url_for
from flask_security import Security, login_required, current_user, utils, \
     SQLAlchemySessionUserDatastore
     
from flask_admin import Admin
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers

from wtforms.fields import PasswordField

from database import db_session, init_db
from models import User, Role

import os


# Create app
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SECURITY_PASSWORD_SALT'] = os.environ['SECURITY_PASSWORD_SALT']
#app.config['SECURITY_URL_PREFIX'] = "/auth"
app.config['SECURITY_POST_LOGIN_VIEW'] = "/auth/"
app.config['SECURITY_POST_LOGOUT_VIEW'] = "/auth/"
app.config['SECURITY_TRACKABLE'] = False

# Setup Flask-Security
user_datastore = SQLAlchemySessionUserDatastore(db_session, User, Role)
security = Security(app, user_datastore)

# Setup database and create admin user
@app.before_first_request
def before_first_request():
    init_db()
    # create admin user if it doesn't exist
    if not user_datastore.get_user(os.environ['ADMIN_USERID']):
        user_datastore.create_user(email=os.environ['ADMIN_USERID'], password=os.environ['ADMIN_PASSWORD'])
        
    # Create the Roles "admin" and "end-user" -- unless they already exist
    user_datastore.find_or_create_role(name='admin', description='Administrator')
    user_datastore.find_or_create_role(name='user', description='User')
    # commit before we use roles and users
    db_session.commit()
    # add admin role
    user_datastore.add_role_to_user(os.environ['ADMIN_USERID'], 'admin')
    db_session.commit()


# Views
@app.route('/')
def index():
    # use flask-admin page template
    return render_template('index.html',         
                           admin_base_template=admin.base_template,
                           admin_view=admin.index_view,
                           h=admin_helpers,
                           get_url=url_for)

@app.route('/hello')
def hello():
    return 'Hello!'

# Views
@app.route('/query_auth', methods=['GET'])
def validate():
    """
    Endpoint used by nginx auth_request.
    
    Gets a GET request without body for every request to the resource.
    Returns 2xx for access granted and 4xx for access denied.
    """
    #app.logger.debug('headers: %s'%request.headers)
    #uri = request.headers.get('Original-Uri')
    if current_user.is_authenticated:
        return 'OK'
    else:
        abort(403)


# Customized User model for SQL-Admin
class UserAdmin(sqla.ModelView):

    # Don't display the password on the list of Users
    column_exclude_list = ('password',)

    # Don't include the standard password field when creating or editing a User (but see below)
    form_excluded_columns = ('password', 'last_login_at', 'current_login_at', 'last_login_ip',
                             'current_login_ip', 'login_count', 'confirmed_at')

    # Automatically display human-readable names for the current and available Roles when creating or editing a User
    column_auto_select_related = True

    # Prevent administration of Users unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        return current_user.has_role('admin')

    # On the form for creating or editing a User, don't display a field corresponding to the model's password field.
    # There are two reasons for this. First, we want to encrypt the password before storing in the database. Second,
    # we want to use a password field (with the input masked) rather than a regular text field.
    def scaffold_form(self):

        # Start with the standard form as provided by Flask-Admin. We've already told Flask-Admin to exclude the
        # password field from this form.
        form_class = super(UserAdmin, self).scaffold_form()

        # Add a password field, naming it "password2" and labeling it "New Password".
        form_class.password2 = PasswordField('New Password')
        return form_class

    # This callback executes when the user saves changes to a newly-created or edited User -- before the changes are
    # committed to the database.
    def on_model_change(self, form, model, is_created):

        # If the password field isn't blank...
        if len(model.password2):

            # ... then encrypt the new password prior to storing it in the database. If the password field is blank,
            # the existing password in the database will be retained.
            model.password = utils.encrypt_password(model.password2)


# Customized Role model for SQL-Admin
class RoleAdmin(sqla.ModelView):

    # Prevent administration of Roles unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        return current_user.has_role('admin')

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


# magic to mount app with prefix when run locally
# def simple(env, resp):
#     resp(b'200 OK', [(b'Content-Type', b'text/plain')])
#     return [b'Hello WSGI World']
# 
# app.wsgi_app = DispatcherMiddleware(simple, {'/auth': app.wsgi_app})

if __name__ == '__main__':
    app.run()
