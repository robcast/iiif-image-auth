# ismi-imageserver

IIIF Image server setup for ISMI project

This Docker setup uses [IIPImage](https://github.com/ruven/iipsrv) server built with 
[OpenJPEG](https://github.com/uclouvain/openjpeg) for JPEG2000 image support.

Serves images through IIIF Image API at http://www.example.com/iiif/images/ and 
IIIF Presentation API files at http://www.example.com/iiif/manifests/ .

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

Runs image server and proxy at port 80.
