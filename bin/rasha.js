#!/usr/bin/env node
'use strict';

var fs = require('fs');
var Rasha = require('../index.js');
var PEM = require('../lib/pem.js');
var ASN1 = require('../lib/asn1.js');

var infile = process.argv[2];
var format = process.argv[3];
var msg = process.argv[4];
var sign;
if ('sign' === format) {
  sign = true;
  format = 'pkcs8';
}

if (!infile) {
  infile = 'jwk';
}

if (-1 !== [ 'jwk', 'pem', 'json', 'der', 'pkcs1', 'pkcs8', 'spki' ].indexOf(infile)) {
  console.log("Generating new key...");
  Rasha.generate({
    format: infile
  , modulusLength: parseInt(format, 10) || 2048
  , encoding: parseInt(format, 10) ? null : format
  }).then(function (key) {
    if ('der' === infile || 'der' === format) {
      key.private = key.private.toString('binary');
      key.public = key.public.toString('binary');
    }
    console.log(key.private);
    console.log(key.public);
  }).catch(function (err) {
    console.error(err);
    process.exit(1);
  });
  return;
}
var key = fs.readFileSync(infile, 'ascii');

try {
  key = JSON.parse(key);
} catch(e) {
  // ignore
}

if ('string' === typeof key) {
  if ('tpl' === format) {
    var block = PEM.parseBlock(key);
    var asn1 = ASN1.parse(block.der);
    ASN1.tpl(asn1);
    return;
  }
  if (sign) { signMessage(key, msg); return; }

  var pub = (-1 !== [ 'public', 'spki', 'pkix' ].indexOf(format));
  Rasha.import({ pem: key, public: (pub || format) }).then(function (jwk) {
    console.info(JSON.stringify(jwk, null, 2));
  }).catch(function (err) {
    console.error(err);
    process.exit(1);
  });
} else {
  Rasha.export({ jwk: key, format: format }).then(function (pem) {
    if (sign) { signMessage(pem, msg); return; }
    console.info(pem);
  }).catch(function (err) {
    console.error(err);
    process.exit(2);
  });
}

function signMessage(pem, name) {
  var msg;
  try {
    msg = fs.readFileSync(name);
  } catch(e) {
    console.warn("[info] input string did not exist as a file, signing the string itself");
    msg = Buffer.from(name, 'binary');
  }
  var crypto = require('crypto');
  var sign = crypto.createSign('SHA256');
  sign.write(msg)
  sign.end()
  var buf = sign.sign(pem);
  console.log(buf.toString('base64'));
  /*
  Rasha.sign({ pem: pem, message: msg, alg: 'SHA256' }).then(function (sig) {
  }).catch(function () {
    console.error(err);
    process.exit(3);
  });
  */
}
