'use strict';

var SSH = module.exports;
var Enc = require('./encoding.js');

              //  7  s  s  h  -  r  s  a
SSH.RSA = '00000007 73 73 68 2d 72 73 61'.replace(/\s+/g, '').toLowerCase();

SSH.parse = function (pem, jwk) {

  var parts = pem.split(/\s+/);
  var buf = Enc.base64ToBuf(parts[1]);
  var els = [];
  var index = 0;
  var len;
  var i = 0;
  var offset = (buf.byteOffset || 0);
  // using dataview to be browser-compatible (I do want _some_ code reuse)
  var dv = new DataView(buf.buffer.slice(offset, offset + buf.byteLength));

  if (SSH.RSA !== Enc.bufToHex(buf.slice(0, SSH.RSA.length/2))) {
    throw new Error("does not lead with ssh header");
  }

  while (index < buf.byteLength) {
    i += 1;
    if (i > 3) { throw new Error("15+ elements, probably not a public ssh key"); }
    len = dv.getUint32(index, false);
    index += 4;
    els.push(buf.slice(index, index + len));
    index += len;
  }

  jwk.n = Enc.bufToUrlBase64(els[2]);
  jwk.e = Enc.bufToUrlBase64(els[1]);

  return jwk;
};
