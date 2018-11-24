#!/usr/bin/env node
'use strict';

var fs = require('fs');
var Rasha = require('../index.js');
var PEM = require('../lib/pem.js');
var ASN1 = require('../lib/asn1.js');

var infile = process.argv[2];
var format = process.argv[3];

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
    console.log(key.private);
    console.log(key.public);
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
  var pub = (-1 !== [ 'public', 'spki', 'pkix' ].indexOf(format));
  Rasha.import({ pem: key, public: (pub || format) }).then(function (jwk) {
    console.info(JSON.stringify(jwk, null, 2));
  }).catch(function (err) {
    console.error(err);
    process.exit(1);
  });
} else {
  Rasha.export({ jwk: key, format: format }).then(function (pem) {
    console.info(pem);
  }).catch(function (err) {
    console.error(err);
    process.exit(2);
  });
}
