'use strict';

var Enc = module.exports;

Enc.bufToHex = function toHex(u8) {
  var hex = [];
  var i, h;
  var len = (u8.byteLength || u8.length);

  for (i = 0; i < len; i += 1) {
    h = u8[i].toString(16);
    if (2 !== h.length) { h = '0' + h; }
    hex.push(h);
  }

  return hex.join('').toLowerCase();
};

Enc.hexToBase64 = function (hex) {
  return Buffer.from(hex, 'hex').toString('base64');
};

Enc.hexToBuf = function (hex) {
  return Buffer.from(hex, 'hex');
};

Enc.numToHex = function numToHex(d) {
  d = d.toString(16);
  if (d.length % 2) {
    return '0' + d;
  }
  return d;
};

Enc.base64ToHex = function base64ToHex(b64) {
  return Enc.bufToHex(Enc.base64ToBuf(b64));
};

Enc.bufToBase64 = function toHex(u8) {
  // we want to maintain api compatability with browser APIs,
  // so we assume that this could be a Uint8Array
  return Buffer.from(u8).toString('base64');
};

/*
Enc.bufToUint8 = function bufToUint8(buf) {
  return new Uint8Array(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
};
*/

Enc.bufToUrlBase64 = function toHex(u8) {
  return Enc.bufToBase64(u8)
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

Enc.strToHex = function strToHex(str) {
  return Buffer.from(str).toString('hex');
};

Enc.strToBuf = function strToBuf(str) {
  return Buffer.from(str);
};

/*
Enc.strToBin = function strToBin(str) {
  var escstr = encodeURIComponent(str);
  // replaces any uri escape sequence, such as %0A,
  // with binary escape, such as 0x0A
  var binstr = escstr.replace(/%([0-9A-F]{2})/g, function(match, p1) {
    return String.fromCharCode(parseInt(p1, 16));
  });

  return binstr;
};
*/

/*
Enc.strToBase64 = function strToBase64(str) {
  // node automatically can tell the difference
  // between uc2 (utf-8) strings and binary strings
  // so we don't have to re-encode the strings
  return Buffer.from(str).toString('base64');
};
*/

/*
Enc.urlBase64ToBase64 = function urlsafeBase64ToBase64(str) {
  var r = str % 4;
  if (2 === r) {
    str += '==';
  } else if (3 === r) {
    str += '=';
  }
  return str.replace(/-/g, '+').replace(/_/g, '/');
};
*/

Enc.base64ToBuf = function base64ToBuf(str) {
  // always convert from urlsafe base64, just in case
  //return Buffer.from(Enc.urlBase64ToBase64(str)).toString('base64');
  // node handles urlBase64 automatically
  return Buffer.from(str, 'base64');
};
