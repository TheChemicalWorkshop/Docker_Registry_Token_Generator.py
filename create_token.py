import jwt
import time
import datetime
import random
import secrets
import os, sys


# * ------------------------ KID GENERATION ------------------------ 

from OpenSSL import crypto 
import re
import base64
import hashlib

def create_kid(public_key_bytes):


    # * load the certificate (bytes) as X509 object
    crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, public_key_bytes)

    # * extract the PUBLIC KEY object out of the X509 object
    pubKeyObject = crtObj.get_pubkey()

    # * convert PUBLIC KEY object into actual public key bytes and convert to String
    pubKeyStringBytes = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
    pubKeyString = pubKeyStringBytes.decode("ascii") 

    # * strip out BEGIN PUBLIC KEY, you can make this nicer to strip out other headers/footers
    result = re.search(r"-----BEGIN PUBLIC KEY-----\n(.*)\n-----END PUBLIC KEY-----\n", pubKeyString, flags=re.DOTALL)

    # * Extract actual public key of the public key
    public_key_content = (result.groups()[0])

    # * convert public key into DER key by encoding with base64, output as hex
    der_public_key = base64.b64decode(public_key_content).hex()

    # * hash der_public_key (needs to by bytes first), outputs hash bytes
    der_public_key_hash = hashlib.sha256(bytes.fromhex(der_public_key)).digest()

    # * shorten the hash to 30 characters
    short_der_public_key_hash = der_public_key_hash[:30]

    # * base32 encode the hash bytes
    der_public_key_hash_base32 = base64.b32encode(short_der_public_key_hash)

    # * convert to ascii
    raw_kid = der_public_key_hash_base32.decode("ascii")

    # do some magic i dont understand
    # stolen from https://github.com/tswayne/js-libtrust/blob/main/index.js
    kid = ""
    i = 1

    for i in range(0, 48):
        kid += raw_kid[i]
        if (i % 4 == 3 and (i + 1) != 48):
            kid += ":"

    return kid


# with open("public_key", "rb") as f:
#     pem_certificate = f.read()

# create_kid(pem_certificate)


# * ------------------------ KID GENERATION ------------------------ 


def generate_token(\
    sub,
    repository_name="",
    expiration_hours = 6, \
    iss="The Chemical Workshop", \
    aud="dockerhub.thechemicalworkshop.com"):


    dir = os.path.dirname(__file__)

    with open(os.path.join(dir, 'public_key'), "rb") as f:
        public_key = f.read()

    with open(os.path.join(dir, 'private_key'), "rb") as f:
        private_key = f.read()


    now = datetime.datetime.now()

    # expiration time

    expiration_time = now + datetime.timedelta(hours=expiration_hours)

    expiration_time_unix = int(time.mktime(expiration_time.timetuple()))

    # now time

    now_time_unix = int(time.mktime(now.timetuple()))

    # not before time

    not_before_time = now + datetime.timedelta(seconds=-10)

    not_before_time_unix = int(time.mktime(not_before_time.timetuple()))




    encoded = jwt.encode(\
        {\
            "iss": iss, \
            "aud": aud,\
            "sub": sub,\
            "jti": str(secrets.token_hex(16)),\
            "nbf": not_before_time_unix,\
            "exp": expiration_time_unix,\
            "iat": now_time_unix,\
            "access": [
                {
                    "type": "repository",
                    "name": repository_name,
                    "actions": ["*"]
                },
                {
                    "type": "registry",
                    "name": "Catalog",
                    "actions": ["*"]
                },
                    ]
        }, \
            private_key, algorithm="RS256", headers={"kid": create_kid(public_key)})

    return encoded

# {
#     "type": "registry",
#     "name": "Catalog",
#     "actions": ["*"]
# }
# you can delete this if you want, this gives you some extra access



# ! docker Linux Host
# sudo docker version
# Client: Docker Engine - Community
#  Version:           20.10.14
#  API version:       1.41
#  Go version:        go1.16.15
#  Git commit:        a224086
#  Built:             Thu Mar 24 01:48:02 2022
#  OS/Arch:           linux/amd64
#  Context:           default
#  Experimental:      true

# Server: Docker Engine - Community
#  Engine:
#   Version:          20.10.14
#   API version:      1.41 (minimum version 1.12)
#   Go version:       go1.16.15
#   Git commit:       87a90dc
#   Built:            Thu Mar 24 01:45:53 2022
#   OS/Arch:          linux/amd64
#   Experimental:     false
#  containerd:
#   Version:          1.5.11
#   GitCommit:        3df54a852345ae127d1fa3092b95168e4a88e2f8
#  runc:
#   Version:          1.0.3
#   GitCommit:        v1.0.3-0-gf46b6ba
#  docker-init:
#   Version:          0.19.0
#   GitCommit:        de40ad0

# linux host pip list (you don't need all of this, i have junk)

# Package                  Version
# ------------------------ -------------------
# aiofiles                 0.7.0
# aiohttp                  3.7.3
# async-timeout            3.0.1
# asyncpg                  0.24.0
# attrs                    20.3.0
# blinker                  1.4
# cachetools               4.2.2
# certifi                  2020.12.5
# cffi                     1.15.0
# chardet                  3.0.4
# charset-normalizer       2.0.3
# click                    7.1.2
# cryptography             37.0.1
# discord.py               1.6.0
# google-api-core          1.31.1
# google-api-python-client 2.15.0
# google-auth              1.34.0
# google-auth-httplib2     0.1.0
# googleapis-common-protos 1.53.0
# h11                      0.12.0
# h2                       4.1.0
# hpack                    4.0.0
# httplib2                 0.19.1
# Hypercorn                0.11.2
# hyperframe               6.0.1
# idna                     3.1
# itsdangerous             1.1.0
# Jinja2                   2.11.3
# MarkupSafe               1.1.1
# multidict                5.1.0
# packaging                21.0
# pip                      20.3.3
# priority                 2.0.0
# protobuf                 3.17.3
# pyasn1                   0.4.8
# pyasn1-modules           0.2.8
# pycparser                2.21
# PyJWT                    2.3.0
# pyOpenSSL                22.0.0
# pyparsing                2.4.7
# pytz                     2021.1
# Quart                    0.15.1
# redis                    3.5.3
# requests                 2.26.0
# rsa                      4.7.2
# setuptools               52.0.0.post20210125
# six                      1.16.0
# toml                     0.10.2
# typing-extensions        3.7.4.3
# uritemplate              3.0.1
# urllib3                  1.26.6
# Werkzeug                 2.0.2
# wheel                    0.36.2
# wsproto                  1.0.0
# yarl                     1.6.3


# WINDOWS docker details
# i use windows to docker login 

# (base) PS C:\Users\Matti> docker version
# Client:
#  Cloud integration: v1.0.24
#  Version:           20.10.14
#  API version:       1.41
#  Go version:        go1.16.15
#  Git commit:        a224086
#  Built:             Thu Mar 24 01:53:11 2022
#  OS/Arch:           windows/amd64
#  Context:           default
#  Experimental:      true

# Server: Docker Desktop 4.8.0 (78933)
#  Engine:
#   Version:          20.10.14
#   API version:      1.41 (minimum version 1.12)
#   Go version:       go1.16.15
#   Git commit:       87a90dc
#   Built:            Thu Mar 24 01:46:14 2022
#   OS/Arch:          linux/amd64
#   Experimental:     false
#  containerd:
#   Version:          1.5.11
#   GitCommit:        3df54a852345ae127d1fa3092b95168e4a88e2f8
#  runc:
#   Version:          1.0.3
#   GitCommit:        v1.0.3-0-gf46b6ba
#  docker-init:
#   Version:          0.19.0
#   GitCommit:        de40ad0

