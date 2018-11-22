'use strict';

var PEM = module.exports;
var Enc = require('./encoding.js');

PEM.RSA_OBJID = '06 09 2A864886F70D010101'
  .replace(/\s+/g, '').toLowerCase();

PEM.parseBlock = function pemToDer(pem) {
  var typ;
  var pub;
  var hex;
  var der = Enc.base64ToBuf(pem.split(/\n/).filter(function (line, i) {
    if (0 === i) {
      if (/ PUBLIC /.test(line)) {
        pub = true;
      } else if (/ PRIVATE /.test(line)) {
        pub = false;
      }
      if (/ RSA /.test(line)) {
        typ = 'RSA';
      }
    }
    return !/---/.test(line);
  }).join(''));

  if (!typ) {
    hex = Enc.bufToHex(der);
    if (-1 !== hex.indexOf(PEM.RSA_OBJID)) {
      typ = 'RSA';
    }
  }
  if (!typ) {
    console.warn("Definitely not an RSA PKCS#8 because there's no RSA Object ID in the DER body.");
    console.warn("Probably not an RSA PKCS#1 because 'RSA' wasn't in the PEM type string.");
  }

  return { kty: typ, pub: pub, der: der };
};
