#!/bin/bash

node bin/rasha.js ./fixtures/privkey-rsa-2048.pkcs1.pem
node bin/rasha.js ./fixtures/privkey-rsa-2048.pkcs8.pem
node bin/rasha.js ./fixtures/pub-rsa-2048.pkcs1.pem
node bin/rasha.js ./fixtures/pub-rsa-2048.spki.pem
