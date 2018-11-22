#!/usr/bin/env node
'use strict';
var fs = require('fs');
var infile = process.argv[2];

var pem = fs.readFileSync(infile, 'ascii');
var b64 = pem.split(/\n/).filter(function (line) {
  // TODO test if RSA key
  if (/^---/.test(line)) {
    return false;
  }
  return true;
}).join('');
var buf = Buffer.from(b64, 'base64');

var ELOOP = "uASN1.js Error: iterated over 100+ elements (probably a malformed file)";
var EDEEP = "uASN1.js Error: element nested 100+ layers deep (probably a malformed file)";
var ASN1 = require('../lib/uasn1.js');
/*
function ASN1(buf, depth) {
  if (depth >= 100) {
    throw new Error(EDEEP);
  }

  // start after type (0) and lengthSize (1)
  var index = 2;
  var asn1 = {
    type: buf[0]
  , lengthSize: 0
  , length: buf[1]
  };
  var child;
  var i = 0;
  if (0x80 & asn1.length) {
    asn1.lengthSize = 0x7f & asn1.length;
    // I think that buf->hex->int solves the problem of Endianness... not sure
    asn1.length = parseInt(buf.slice(index, index + asn1.lengthSize).toString('hex'), 16);
    // add back the original byte indicating lengthSize
    index += 1;
  }

  // this is a primitive value type
  if (asn1.type <= 0x06) {
    i += 1;
    asn1.value = buf.slice(index, index + asn1.length);
    return asn1;
  }

  asn1.children = [];
  while (i < 100 && index < buf.byteLength) {
    child = ASN1(buf.slice(index), (depth || 0) + 1);
    index += (2 + child.lengthSize + child.length);
    asn1.children.push(child);
  }
  if (i >= 100) { throw new Error(ELOOP); }

  return asn1;
}
*/

var asn1 = ASN1.parse(buf);
var ws = '';
function write(asn1) {
  console.log(ws, 'ch', Buffer.from([asn1.type]).toString('hex'), asn1.length);
  if (!asn1.children) {
    return;
  }
  asn1.children.forEach(function (a, i) {
    ws += '\t';
    write(a);
    ws = ws.slice(1);
  });
}
console.log(asn1);
write(asn1);
