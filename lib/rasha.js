'use strict';

var RSA = module.exports;
var ASN1 = require('./asn1.js');
//var Enc = require('./encoding.js');
var PEM = require('./pem.js');
var SSH = require('./ssh.js');


/*
RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
*/

/*global Promise*/
RSA.parse = function parseEc(opts) {
  return Promise.resolve().then(function () {
    if (!opts || !opts.pem || 'string' !== typeof opts.pem) {
      throw new Error("must pass { pem: pem } as a string");
    }
    if (0 === opts.pem.indexOf('ssh-rsa ')) {
      return SSH.parse(opts.pem);
    }
    var pem = opts.pem;
    var block = PEM.parseBlock(pem);
    //var hex = toHex(u8);
    //var jwk = { kty: 'RSA' };

    var asn1 = ASN1.parse(block.der);
    var ws = '';
    function write(asn1) {
      console.log(ws, 'ch', Buffer.from([asn1.type]).toString('hex'), asn1.length);
      if (!asn1.children) {
        return;
      }
      asn1.children.forEach(function (a) {
        ws += '\t';
        write(a);
        ws = ws.slice(1);
      });
    }
    //console.log(JSON.stringify(asn1, null, 2));
    console.log(asn1);
    write(asn1);

    return { kty: 'RSA' };
  });
};
RSA.toJwk = RSA.import = RSA.parse;
