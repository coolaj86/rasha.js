'use strict';

//var ASN1 = require('./asn1.js');
var x509 = module.exports;

x509.guess = function (der, asn1) {
  // accepting der for compatability with other usages

  var meta = { kty: 'RSA', format: 'pkcs1', public: true };
  //meta.asn1 = ASN1.parse(u8);

  if (asn1.children.every(function(el) {
    return 0x02 === el.type;
  })) {
    if (2 === asn1.children.length) {
      // rsa pkcs1 public
      return meta;
    } else if (asn1.children.length >= 9) {
      // the standard allows for "otherPrimeInfos", hence at least 9
      meta.public = false;
      // rsa pkcs1 private
      return meta;
    } else {
      throw new Error("not an RSA PKCS#1 public or private key (wrong number of ints)");
    }
  } else {
    meta.format = 'pkcs8';
  }

  return meta;
};
