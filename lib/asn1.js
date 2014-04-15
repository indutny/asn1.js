var asn1 = exports;

// Optional bignum
try {
  asn1.bignum = require('bignum');
} catch (e) {
  asn1.bignum = null;
}

asn1.define = require('./asn1/api').define;
asn1.base = require('./asn1/base');
asn1.constants = require('./asn1/constants');
asn1.decoders = require('./asn1/decoders');
asn1.encoders = require('./asn1/encoders');
