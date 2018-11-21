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

function ASN1(buf, depth) {
  console.log();
  if (!depth) { depth = 0; }
  if (depth >= 15) {
    throw new Error("We got stuck in a loop (or this is actually more than 15 layers deep, which we never expected)");
  }
  var asn1 = {
    type: buf[0]
  , length: 0
  , lengthLength: buf[1]
  , totalLength: 0
  , value: null
  , children: []
  };
  console.log(depth, buf.byteLength, buf);
  var index = 2;
  var child;
  var i = 0;
  if (0x80 & asn1.lengthLength) {
    asn1.lengthLength = 0x7f & asn1.lengthLength;
    // to not worry about Endianness:
    console.log('lenlen:', buf.slice(index, index + asn1.lengthLength).toString('hex'));
    asn1.length = parseInt(buf.slice(index, index + asn1.lengthLength).toString('hex'), 16);
    index += asn1.lengthLength;
  } else {
    asn1.length = asn1.lengthLength;
    asn1.lengthLength = 0;
  }
  asn1.totalLength += asn1.lengthLength + 1;
  console.log('asn1:'
    , Buffer.from([asn1.type]).toString('hex')
    , Buffer.from([asn1.totalLength])
    , asn1.length
    , asn1.type <= 0x06
  );

  // this is a primitive value type
  if (asn1.type <= 0x06) {
    i += 1;
    asn1.value = buf.slice(index, index + asn1.length);
    console.log("type is less than or equal to 0x06 and value size is", asn1.value.byteLength
      , Buffer.from(asn1.value.slice(asn1.value.byteLength - 3)).toString('hex'));
    return asn1;
  }

  while (i < 12 && index < buf.byteLength) {
    child = ASN1(buf.slice(index), depth += 1);
    index += 1 /*child.type.length*/ + child.totalLength + child.length;
    console.log("New Index is:", index, "New buf.byteLength:", buf.byteLength);
    asn1.children.push(child);
  }

  if (i >= 12) {
    throw new Error("malformed ASN1: got stuck in a read loop (or there were actually 100+ elements in a sequence, which we never expected)");
  }

  return asn1;
}

console.log(ASN1(buf));
