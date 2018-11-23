#!/bin/bash
set -e

echo ""
echo ""
echo "Testing PEM-to-JWK PKCS#1"
echo ""
#
node bin/rasha.js ./fixtures/privkey-rsa-2048.pkcs1.pem > ./fixtures/privkey-rsa-2048.jwk.1.json
diff ./fixtures/privkey-rsa-2048.jwk.json ./fixtures/privkey-rsa-2048.jwk.1.json
#
node bin/rasha.js ./fixtures/pub-rsa-2048.pkcs1.pem > ./fixtures/pub-rsa-2048.jwk.1.json
diff ./fixtures/pub-rsa-2048.jwk.json ./fixtures/pub-rsa-2048.jwk.1.json


echo ""
echo ""
echo "Testing PEM-to-JWK PKCS#8"
echo ""
#
node bin/rasha.js ./fixtures/privkey-rsa-2048.pkcs8.pem > ./fixtures/privkey-rsa-2048.jwk.1.json
diff ./fixtures/privkey-rsa-2048.jwk.json ./fixtures/privkey-rsa-2048.jwk.1.json
#
node bin/rasha.js ./fixtures/pub-rsa-2048.spki.pem > ./fixtures/pub-rsa-2048.jwk.1.json
diff ./fixtures/pub-rsa-2048.jwk.json ./fixtures/pub-rsa-2048.jwk.1.json


echo ""
echo ""
echo "Testing JWK-to-PEM PKCS#1"
echo ""
#
node bin/rasha.js ./fixtures/privkey-rsa-2048.jwk.json pkcs1 > ./fixtures/privkey-rsa-2048.pkcs1.1.pem
diff ./fixtures/privkey-rsa-2048.pkcs1.pem ./fixtures/privkey-rsa-2048.pkcs1.1.pem
#
node bin/rasha.js ./fixtures/pub-rsa-2048.jwk.json pkcs1 > ./fixtures/pub-rsa-2048.pkcs1.1.pem
diff ./fixtures/pub-rsa-2048.pkcs1.pem ./fixtures/pub-rsa-2048.pkcs1.1.pem


#echo ""
#echo ""
#echo "Testing JWK-to-PEM PKCS#8"
#echo ""
#
#node bin/rasha.js ./fixtures/privkey-rsa-2048.jwk.json pkcs8 > ./fixtures/privkey-rsa-2048.pkcs8.1.pem
#diff ./fixtures/privkey-rsa-2048.pkcs8.pem ./fixtures/privkey-rsa-2048.pkcs8.1.pem
#
#node bin/rasha.js ./fixtures/pub-rsa-2048.jwk.json spki > ./fixtures/pub-rsa-2048.spki.1.pem
#diff ./fixtures/pub-rsa-2048.pski.pem ./fixtures/pub-rsa-2048.spki.1.pem


echo ""
echo ""
echo "Testing JWK-to-SSH"
echo ""
#
node bin/rasha.js ./fixtures/privkey-rsa-2048.jwk.json ssh > ./fixtures/pub-rsa-2048.ssh.1.pub
diff ./fixtures/pub-rsa-2048.ssh.pub ./fixtures/pub-rsa-2048.ssh.1.pub
#
node bin/rasha.js ./fixtures/pub-rsa-2048.jwk.json ssh > ./fixtures/pub-rsa-2048.ssh.1.pub
diff ./fixtures/pub-rsa-2048.ssh.pub ./fixtures/pub-rsa-2048.ssh.1.pub

rm fixtures/*.1.*

echo ""
echo ""
echo "PASSED:"
echo "• All inputs produced valid outputs"
echo "• All outputs matched known-good values"
echo ""
