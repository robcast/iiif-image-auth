#!/bin/sh

PROTO=${VIRTUAL_HOST_PROTO:-https}
HOST="${PROTO}://${VIRTUAL_HOST:?virtual host missing}"

INFO_JSON=${1:-auth-img.json}

# generate info.json using ENV
cat <<EOF > $INFO_JSON
{
    "@context": "http://iiif.io/api/image/2/context.json",
    "@id": "${HOST}/iiif/images/auth-image.jpg",
    "protocol": "http://iiif.io/api/image",
    "width": 1234,
    "height": 1234,
    "profile": [
        "http://iiif.io/api/image/2/level1.json"
    ],
    "service": {
        "@context": "http://iiif.io/api/auth/1/context.json",
        "@id": "${HOST}/auth/iiif-login",
        "profile": "http://iiif.io/api/auth/1/login",
        "label": "Login to image server",
        "header": "Please Log In",
        "description": "Log in to the image authentication server to view this content.",
        "confirmLabel": "Login",
        "failureHeader": "Authentication Failed",
        "failureDescription": "The log in attempt failed.",
        "service": [
            {
                "@id": "${HOST}/auth/iiif-token",
                "profile": "http://iiif.io/api/auth/1/token"
            },
            {
                "@id": "${HOST}/auth/logout",
                "profile": "http://iiif.io/api/auth/1/logout",
                "label": "Log out from image server"
            }
        ]
    }
}
EOF

echo "created $INFO_JSON"
