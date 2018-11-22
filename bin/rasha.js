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
    index: 2 // start after type (0) and lengthSize (1)
  , type: buf[0]
  , length: buf[1]
  , lengthSize: 0
  , value: null
  , children: []
  };
  console.log(depth, buf.byteLength, buf);
  var child;
  var i = 0;
  if (0x80 & asn1.length) {
    asn1.lengthSize = 0x7f & asn1.length;
    // I think that buf->hex->int solves the problem of Endianness... not sure
    console.log('lenlen:', buf.slice(asn1.index, asn1.index + asn1.lengthSize).toString('hex'));
    asn1.length = parseInt(buf.slice(asn1.index, asn1.index + asn1.lengthSize).toString('hex'), 16);
    // add back the original byte indicating lengthSize
    //asn1.lengthSize += 1;
    //asn1.index += asn1.lengthSize;
    asn1.index += 1;
  }

  console.log('asn1', 'type', Buffer.from([asn1.type]).toString('hex')
    , 'ls', Buffer.from([asn1.lengthSize]).toString('hex'), 'len', asn1.length
    , 'ch', asn1.children.length, 'vlen', asn1.value && asn1.value.length || null);

  // this is a primitive value type
  if (asn1.type <= 0x06) {
    i += 1;
    asn1.value = buf.slice(asn1.index, asn1.index + asn1.length);
    return asn1;
  }

  while (i < 12 && asn1.index < buf.byteLength) {
    var childbuf = buf.slice(asn1.index);
    child = ASN1(childbuf, depth += 1);
    console.log('child', 'type', Buffer.from([child.type]).toString('hex')
      , 'ls', Buffer.from([child.lengthSize]).toString('hex'), 'len', child.length
      , 'ch', child.children.length, 'vlen', child.value && child.value.length || null);
    asn1.index += 2 /*child.type.length*/ + child.lengthSize + child.length;
    asn1.children.push(child);
  }

  if (i >= 12) {
    throw new Error("malformed ASN1: got stuck in a read loop (or there were actually 100+ elements in a sequence, which we never expected)");
  }

  return asn1;
}

console.log(ASN1(buf));
