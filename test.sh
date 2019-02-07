#!/bin/bash

# cause errors to hard-fail
# (and diff non-0 exit status will cause failure)
set -e

pemtojwk() {
	keyid=$1
  if [ -z "$keyid" ]; then
    echo ""
    echo "Testing PEM-to-JWK PKCS#1"
  fi
	#
	node bin/rasha.js ./fixtures/privkey-rsa-2048.pkcs1.${keyid}pem \
    > ./fixtures/privkey-rsa-2048.jwk.1.json
	diff ./fixtures/privkey-rsa-2048.jwk.${keyid}json ./fixtures/privkey-rsa-2048.jwk.1.json
	#
	node bin/rasha.js ./fixtures/pub-rsa-2048.pkcs1.${keyid}pem \
    > ./fixtures/pub-rsa-2048.jwk.1.json
	diff ./fixtures/pub-rsa-2048.jwk.${keyid}json ./fixtures/pub-rsa-2048.jwk.1.json
  if [ -z "$keyid" ]; then
    echo "Pass"
  fi


  if [ -z "$keyid" ]; then
    echo ""
    echo "Testing PEM-to-JWK PKCS#8"
  fi
	#
	node bin/rasha.js ./fixtures/privkey-rsa-2048.pkcs8.${keyid}pem \
    > ./fixtures/privkey-rsa-2048.jwk.1.json
	diff ./fixtures/privkey-rsa-2048.jwk.${keyid}json ./fixtures/privkey-rsa-2048.jwk.1.json
	#
	node bin/rasha.js ./fixtures/pub-rsa-2048.spki.${keyid}pem \
    > ./fixtures/pub-rsa-2048.jwk.1.json
	diff ./fixtures/pub-rsa-2048.jwk.${keyid}json ./fixtures/pub-rsa-2048.jwk.1.json
  if [ -z "$keyid" ]; then
    echo "Pass"
  fi
}

jwktopem() {
	keyid=$1
  if [ -z "$keyid" ]; then
    echo ""
    echo "Testing JWK-to-PEM PKCS#1"
  fi
	#
	node bin/rasha.js ./fixtures/privkey-rsa-2048.jwk.${keyid}json pkcs1 \
    > ./fixtures/privkey-rsa-2048.pkcs1.1.pem
	diff ./fixtures/privkey-rsa-2048.pkcs1.${keyid}pem ./fixtures/privkey-rsa-2048.pkcs1.1.pem
	#
	node bin/rasha.js ./fixtures/pub-rsa-2048.jwk.${keyid}json pkcs1 \
    > ./fixtures/pub-rsa-2048.pkcs1.1.pem
	diff ./fixtures/pub-rsa-2048.pkcs1.${keyid}pem ./fixtures/pub-rsa-2048.pkcs1.1.pem
  if [ -z "$keyid" ]; then
    echo "Pass"
  fi

  if [ -z "$keyid" ]; then
    echo ""
    echo "Testing JWK-to-PEM PKCS#8"
  fi
	#
	node bin/rasha.js ./fixtures/privkey-rsa-2048.jwk.${keyid}json pkcs8 \
    > ./fixtures/privkey-rsa-2048.pkcs8.1.pem
	diff ./fixtures/privkey-rsa-2048.pkcs8.${keyid}pem ./fixtures/privkey-rsa-2048.pkcs8.1.pem
	#
	node bin/rasha.js ./fixtures/pub-rsa-2048.jwk.${keyid}json spki \
    > ./fixtures/pub-rsa-2048.spki.1.pem
	diff ./fixtures/pub-rsa-2048.spki.${keyid}pem ./fixtures/pub-rsa-2048.spki.1.pem
  if [ -z "$keyid" ]; then
    echo "Pass"
  fi

  if [ -z "$keyid" ]; then
    echo ""
    echo "Testing JWK-to-SSH"
  fi
	#
	node bin/rasha.js ./fixtures/privkey-rsa-2048.jwk.${keyid}json ssh > ./fixtures/pub-rsa-2048.ssh.1.pub
	diff ./fixtures/pub-rsa-2048.ssh.${keyid}pub ./fixtures/pub-rsa-2048.ssh.1.pub
	#
	node bin/rasha.js ./fixtures/pub-rsa-2048.jwk.${keyid}json ssh > ./fixtures/pub-rsa-2048.ssh.1.pub
	diff ./fixtures/pub-rsa-2048.ssh.${keyid}pub ./fixtures/pub-rsa-2048.ssh.1.pub
  if [ -z "$keyid" ]; then
    echo "Pass"
  fi
}

rndkey() {
	keyid="rnd.1."
  keysize=$1
	# Generate 2048-bit RSA Keypair
	openssl genrsa -out fixtures/privkey-rsa-2048.pkcs1.${keyid}pem $keysize
	# Convert PKCS1 (traditional) RSA Keypair to PKCS8 format
	openssl rsa -in fixtures/privkey-rsa-2048.pkcs1.${keyid}pem -pubout \
    -out fixtures/pub-rsa-2048.spki.${keyid}pem
	# Export Public-only RSA Key in PKCS1 (traditional) format
	openssl pkcs8 -topk8 -nocrypt -in fixtures/privkey-rsa-2048.pkcs1.${keyid}pem \
    -out fixtures/privkey-rsa-2048.pkcs8.${keyid}pem
	# Convert PKCS1 (traditional) RSA Public Key to SPKI/PKIX format
	openssl rsa -in fixtures/pub-rsa-2048.spki.${keyid}pem -pubin -RSAPublicKey_out \
    -out fixtures/pub-rsa-2048.pkcs1.${keyid}pem
	# Convert RSA public key to SSH format
  sshpub=$(ssh-keygen -f fixtures/pub-rsa-2048.spki.${keyid}pem -i -mPKCS8)
  echo "$sshpub rsa@localhost" > fixtures/pub-rsa-2048.ssh.${keyid}pub


  # to JWK
	node bin/rasha.js ./fixtures/privkey-rsa-2048.pkcs1.${keyid}pem \
    > ./fixtures/privkey-rsa-2048.jwk.${keyid}json
	node bin/rasha.js ./fixtures/pub-rsa-2048.pkcs1.${keyid}pem \
    > ./fixtures/pub-rsa-2048.jwk.${keyid}json

  pemtojwk "$keyid"
  jwktopem "$keyid"
}

pemtojwk ""
jwktopem ""

echo ""
echo "testing node key generation"
node bin/rasha.js > /dev/null
node bin/rasha.js jwk > /dev/null
node bin/rasha.js json 2048 > /dev/null
node bin/rasha.js der > /dev/null
node bin/rasha.js pkcs8 der > /dev/null
node bin/rasha.js pem > /dev/null
node bin/rasha.js pkcs1 pem > /dev/null
node bin/rasha.js spki > /dev/null
echo "PASS"

echo ""
echo ""
echo "Re-running tests with random keys of varying sizes"
echo ""

# commented out sizes below 512, since they are below minimum size on some systems.
# rndkey 32 # minimum key size
# rndkey 64
# rndkey 128
# rndkey 256

rndkey 512
rndkey 768
rndkey 1024
rndkey 2048 # first secure key size

if [ "${RASHA_TEST_LARGE_KEYS}" == "true" ]; then
  rndkey 3072
  rndkey 4096 # largest reasonable key size
else
  echo ""
  echo "Note:"
  echo "Keys larger than 2048 have been tested and work, but are omitted from automated tests to save time."
  echo "Set RASHA_TEST_LARGE_KEYS=true to enable testing of keys up to 4096."
fi

echo ""
echo "Pass"

rm fixtures/*.1.*

echo ""
echo "Testing Thumbprints"
node bin/rasha.js ./fixtures/privkey-rsa-2048.pkcs1.pem thumbprint
node bin/rasha.js ./fixtures/pub-rsa-2048.jwk.json thumbprint
echo "PASS"

echo ""
echo ""
echo "PASSED:"
echo "• All inputs produced valid outputs"
echo "• All outputs matched known-good values"
echo "• All random tests passed reciprosity"
