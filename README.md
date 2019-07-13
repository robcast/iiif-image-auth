# iiif-image-auth

A simple [IIIF-Image API](https://iiif.io/api/image/2.1/) server 
with [IIIF-Auth API](https://iiif.io/api/auth/1.0/) support.

This Docker setup provides:

* [IIPImage](https://github.com/ruven/iipsrv) image service built with 
[OpenJPEG](https://github.com/uclouvain/openjpeg) for JPEG2000 image support
* [Flask](https://palletsprojects.com/p/flask/) authentication web application using 
[Flask-Admin](https://flask-admin.readthedocs.io/) and 
[Flask-Security](https://pythonhosted.org/Flask-Security/)
* [Nginx proxy](https://github.com/jwilder/nginx-proxy) connecting the image and the authentication server 

Images from the configured image folder (`IMAGE_DIR`) are served at the IIIF Image API endpoint at 
http://your.server/iiif/images/ and IIIF Presentation API files from the 
manifest folder (`MANIFEST_DIR`) at http://your.server/iiif/manifests/ 

The authentication server user management frontend can be reached at 
http://your.server/auth/admin/ (initial user: `AUTH_ADMIN_USERID`, `AUTH_ADMIN_PASSWORD`).

All images are accessible for all users defined in the authentication server.
If you want to extend the application to implement more granular permissions
look at `validate()` in [app.py](auth/app.py).

## Requirements

You need Docker and docker-compose.

## Configuration

Create a `.env` file by copying the sample file:
```
cp .env.template .env
```

Edit `.env` and adjust `VIRTUAL_HOST`, `IMAGE_DIR` and `MANIFEST_DIR` for your system.

Add secrets (random strings) to `AUTH_SECRET_KEY` and `AUTH_PASSWORD_SALT` and user
credentials for the initial admin user in `AUTH_ADMIN_USERID` and `AUTH_ADMIN_PASSWORD`.

Enter a database connection in `AUTH_DB_CONNECTION` (e.g. a sqlite file inside the container).

Add `LETSENCRYPT_EMAIL` for the letsencrypt-proxy-companion.

## Run

```
docker-compose up -d
```

Starts the image and auth server and proxy at port 80 and 443.

The [letsencrypt-proxy-companion](https://github.com/JrCs/docker-letsencrypt-nginx-proxy-companion) 
automatically downloads letsencrypt SSL certificates.

## Implementation details

Authorization for image (and manifest) requests relies on the Nginx 
[http_auth_request](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) module configured 
in the files [default](proxy/vhost.d/default)
and [default_location](proxy/vhost.d/default_location).

For every request by the client to the proxy the proxy makes another request (without body)
to the `query_auth` endpoint in the auth application and forwards the clients original
request only if the auth application returns a 200 result code.

The `query_auth` endpoint checks the clients credentials provided either as a session cookie
of a Flask-Login session or a token in the `Authorization` header.

When the client does not provide the necessary credentials the `query_auth` endpoint returns a
401 error code. In this case the proxy sends a response with a 401 status code to the client 
including a preconfigured manifest or image info document as the message body.
The document includes ULRs for the *Access Cookie Service* and *Access Token Service* service 
endpoints as required by the [IIIF-Auth specification](https://iiif.io/api/auth/1.0/).

The *Access Cookie Service* is implemented by the `/iiif-login` endpoint. It is supposed to be
opened in a separate tab by the IIIF client. It will provide a login form if the user is
not already logged in and try to close the window after a successful login. This interaction
will set a session cookie for the content domain.

The *Access Token Service* is implemented by the `/iiif-token` endpoint. It is supposed to 
be opened in an iframe with a PostMessage handler by the IIIF client. It returns a token
if the request had a session cookie and an error code otherwise.

## Additional configuration

To prevent the letsencrypt-proxy-companion from trying to fetch certificates you can disable the service
by adding a file `docker-compose.override.yml` with the contents:

```
version: '3'

services:
  certbot:
    image: tianon/true 
    restart: "no"
```


## Acknowledgements

The Flask auth app heavily borrowed from [sasaporta/flask-security-admin-example](https://github.com/sasaporta/flask-security-admin-example) and the [flask-admin/flask-admin](https://github.com/flask-admin/flask-admin) examples.
