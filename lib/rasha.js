'use strict';

var RSA = module.exports;
var SSH = require('./ssh.js');
var PEM = require('./pem.js');
var x509 = require('./x509.js');
var ASN1 = require('./asn1.js');

/*global Promise*/
RSA.parse = function parseRsa(opts) {
  return Promise.resolve().then(function () {
    if (!opts || !opts.pem || 'string' !== typeof opts.pem) {
      throw new Error("must pass { pem: pem } as a string");
    }

    var jwk = { kty: 'RSA', n: null, e: null };
    if (0 === opts.pem.indexOf('ssh-rsa ')) {
      return SSH.parse(opts.pem, jwk);
    }
    var pem = opts.pem;
    var block = PEM.parseBlock(pem);
    //var hex = toHex(u8);
    var asn1 = ASN1.parse(block.der);

    var meta = x509.guess(block.der, asn1);

    if ('pkcs1' === meta.format) {
      jwk = x509.parsePkcs1(block.der, asn1, jwk);
    } else {
      jwk = x509.parsePkcs8(block.der, asn1, jwk);
    }

    if (opts.public) {
      jwk = RSA.nueter(jwk);
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

RSA.pack = function (opts) {
  return Promise.resolve().then(function () {
    if (!opts || !opts.jwk || 'object' !== typeof opts.jwk) {
      throw new Error("must pass { jwk: jwk }");
    }
    var jwk = JSON.parse(JSON.stringify(opts.jwk));
    var format = opts.format;
    var pub = opts.public;
    if (pub || -1 !== [ 'spki', 'pkix', 'ssh', 'rfc4716' ].indexOf(format)) {
      jwk = RSA.nueter(jwk);
    }
    if ('RSA' !== jwk.kty) {
      throw new Error("options.jwk.kty must be 'RSA' for RSA keys");
    }
    if (!jwk.p) {
      // TODO test for n and e
      pub = true;
      if (!format || 'pkcs1' === format) {
        format = 'pkcs1';
      } else if (-1 !== [ 'spki', 'pkix' ].indexOf(format)) {
        format = 'spki';
      } else if (-1 !== [ 'ssh', 'rfc4716' ].indexOf(format)) {
        format = 'ssh';
      } else {
        throw new Error("options.format must be 'spki', 'pkcs1', or 'ssh' for public RSA keys, not ("
          + typeof format + ") " + format);
      }
    } else {
      // TODO test for all necessary keys (d, p, q ...)
      if (!format || 'pkcs1' === format) {
        format = 'pkcs1';
      } else if ('pkcs8' !== format) {
        throw new Error("options.format must be 'pkcs1' or 'pkcs8' for private RSA keys");
      }
    }

    if ('pkcs1' === format) {
      if (jwk.d) {
        return PEM.packBlock({ type: "RSA PRIVATE KEY", bytes: x509.packPkcs1(jwk) });
      } else {
        return PEM.packBlock({ type: "RSA PUBLIC KEY", bytes: x509.packPkcs1(jwk) });
      }
    } else if ('pkcs8' === format) {
      return PEM.packBlock({ type: "PRIVATE KEY", bytes: x509.packPkcs8(jwk) });
    } else if (-1 !== [ 'spki', 'pkix' ].indexOf(format)) {
      return PEM.packBlock({ type: "PUBLIC KEY", bytes: x509.packSpki(jwk) });
    } else if (-1 !== [ 'ssh', 'rfc4716' ].indexOf(format)) {
      return SSH.pack({ jwk: jwk, comment: opts.comment });
    } else {
      throw new Error("Sanity Error: reached unreachable code block with format: " + format);
    }
  });
};
RSA.toPem = RSA.export = RSA.pack;

// snip the _private_ parts... hAHAHAHA!
RSA.nueter = function (jwk) {
  // (snip rather than new object to keep potential extra data)
  // otherwise we could just do this:
  // return { kty: jwk.kty, n: jwk.n, e: jwk.e };
  [ 'p', 'q', 'd', 'dp', 'dq', 'qi' ].forEach(function (key) {
    if (key in jwk) { jwk[key] = undefined; }
    return jwk;
  });
  return jwk;
};
