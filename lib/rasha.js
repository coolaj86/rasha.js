'use strict';

var RSA = module.exports;
var ASN1 = require('./asn1.js');
//var Enc = require('./encoding.js');
var PEM = require('./pem.js');
var SSH = require('./ssh.js');
var Enc = require('./encoding.js');


/*global Promise*/
RSA.parse = function parseRsa(opts) {
  return Promise.resolve().then(function () {
    if (!opts || !opts.pem || 'string' !== typeof opts.pem) {
      throw new Error("must pass { pem: pem } as a string");
    }
    if (0 === opts.pem.indexOf('ssh-rsa ')) {
      return SSH.parse(opts.pem);
    }
    var pem = opts.pem;
    var block = PEM.parseBlock(pem);
    var asn1 = ASN1.parse(block.der);
    //var hex = toHex(u8);
    var jwk = { kty: 'RSA' };

    console.log(asn1);
    var len = asn1.children.length;
    if (2 === len || 9 === len) {
      jwk = RSA.parsePkcs1(block.der, asn1, jwk);
    } else {
      jwk = RSA.parsePkcs8(block.der, asn1, jwk);
    }

    return jwk;
  });
};
RSA.toJwk = RSA.import = RSA.parse;

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

RSA.parsePkcs1 = function parseRsaPkcs1(buf, asn1, jwk) {
  if (!asn1.children.every(function(el) {
    return 0x02 === el.type;
  })) {
    throw new Error("not an RSA PKCS#1 public or private key (not all ints)");
  }

  if (2 === asn1.children.length) {

    jwk.n = Enc.bufToUrlBase64(asn1.children[0].value);
    jwk.e = Enc.bufToUrlBase64(asn1.children[1].value);
    return jwk;

  } else if (asn1.children.length >= 9) {
    // the standard allows for "otherPrimeInfos", hence at least 9

    jwk.n = Enc.bufToUrlBase64(asn1.children[1].value);
    jwk.e = Enc.bufToUrlBase64(asn1.children[2].value);
    jwk.d = Enc.bufToUrlBase64(asn1.children[3].value);
    jwk.p = Enc.bufToUrlBase64(asn1.children[4].value);
    jwk.q = Enc.bufToUrlBase64(asn1.children[5].value);
    jwk.dp = Enc.bufToUrlBase64(asn1.children[6].value);
    jwk.dq = Enc.bufToUrlBase64(asn1.children[7].value);
    jwk.qi = Enc.bufToUrlBase64(asn1.children[8].value);

    return jwk;
  } else {
    throw new Error("not an RSA PKCS#1 public or private key (wrong number of ints)");
  }
};
RSA.parsePkcs8 = function parseRsaPkcs8(buf, asn1, jwk) {
};
