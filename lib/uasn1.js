'use strict';

var ELOOP = "uASN1.js Error: iterated over 100+ elements (probably a malformed file)";
var EDEEP = "uASN1.js Error: element nested 100+ layers deep (probably a malformed file)";
// Container Types are Sequence 0x30, Octect String 0x04, Array? (0xA0, 0xA1)
// Value Types are Integer 0x02, Bit String 0x03, Null 0x05, Object ID 0x06,
// Sometimes Bit String is used as a container (RSA Pub Spki)
var VTYPES = [ 0x02, 0x03, 0x05, 0x06 ];

var ASN1 = module.exports = function ASN1() {
};

ASN1.parse = function parseAsn1(buf, depth) {
  console.log('');
  if (depth >= 100) { throw new Error(EDEEP); }

  var index = 2; // we know, at minimum, data starts after type (0) and lengthSize (1)
  var asn1 = { type: buf[0], lengthSize: 0, length: buf[1] };
  var child;
  var iters = 0;
  var adjust = 0;

  // Determine how many bytes the length uses, and what it is
  if (0x80 & asn1.length) {
    asn1.lengthSize = 0x7f & asn1.length;
    // I think that buf->hex->int solves the problem of Endianness... not sure
    asn1.length = parseInt(buf.slice(index, index + asn1.lengthSize).toString('hex'), 16);
    index += asn1.lengthSize;
  }

  // High-order bit Integers have a leading 0x00 to signify that they are positive.
  // Bit Streams use the first byte to signify padding, which x.509 doesn't use.
  console.log(buf[index], asn1.type);
  if (0x00 === buf[index] && (0x02 === asn1.type || 0x03 === asn1.type)) {
    console.log('chomp');
    index += 1;
    adjust = -1;
  }

  // this is a primitive value type
  if (-1 !== VTYPES.indexOf(asn1.type)) {
    asn1.value = buf.slice(index, index + asn1.length + adjust);
    return asn1;
  }

  asn1.children = [];
  while (iters < 100 && index < buf.byteLength) {
    iters += 1;
    child = ASN1.parse(buf.slice(index, index + asn1.length), (depth || 0) + 1);
    index += (2 + child.lengthSize + child.length);
    asn1.children.push(child);
  }
  if (iters >= 100) { throw new Error(ELOOP); }

  return asn1;
};

module.exports = ASN1;
