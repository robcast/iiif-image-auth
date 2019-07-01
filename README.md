# ismi-imageserver

IIIF Image server setup for ISMI project

This Docker setup uses [IIPImage](https://github.com/ruven/iipsrv) server built with 
[OpenJPEG](https://github.com/uclouvain/openjpeg) for JPEG2000 image support.

Serves images through IIIF Image API at http://your.server/iiif/images/ and 
IIIF Presentation API files at http://your.server/iiif/manifests/ .

## Requirements

You need Docker and docker-compose.

## Configuration

```
cp .env.template .env
```

Edit `.env` and adjust `VIRTUAL_HOST`, `IMAGE_DIR` and `MANIFEST_DIR` for your system.

## Run

```
docker-compose up -d
```

Runs image server and proxy at port 80 and 443.

The [letsencrypt-proxy-companion](https://github.com/JrCs/docker-letsencrypt-nginx-proxy-companion) automatically downloads letsencrypt SSL certificates.

## Acknowledgements

The Flask auth app heavily borrowed from [sasaporta/flask-security-admin-example](https://github.com/sasaporta/flask-security-admin-example) and the [flask-admin/flask-admin](https://github.com/flask-admin/flask-admin) examples.
