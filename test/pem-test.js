'use strict';
/* global describe it */

const assert = require('assert');
const asn1 = require('..');
const BN = require('bn.js');

const Buffer = require('buffer').Buffer;

describe('asn1.js PEM encoder/decoder', function() {
  const model = asn1.define('Model', function() {
    this.seq().obj(
      this.key('a').int(),
      this.key('b').bitstr(),
      this.key('c').int()
    );
  });

  const hundred = new Buffer(100);
  hundred.fill('A');

  it('should encode PEM', function() {

    const out = model.encode({
      a: new BN(123),
      b: {
        data: hundred,
        unused: 0
      },
      c: new BN(456)
    }, 'pem', {
      label: 'MODEL'
    });

    const expected =
        '-----BEGIN MODEL-----\n' +
        'MG4CAXsDZQBBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n' +
        'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n' +
        'QUFBQUFBQUFBQUFBAgIByA==\n' +
        '-----END MODEL-----';
    assert.equal(out, expected);
  });

  it('should decode PEM', function() {
    const expected =
        '-----BEGIN MODEL-----\n' +
        'MG4CAXsDZQBBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n' +
        'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n' +
        'QUFBQUFBQUFBQUFBAgIByA==\n' +
        '-----END MODEL-----';

    const out = model.decode(expected, 'pem', { label: 'MODEL' });
    assert.equal(out.a.toString(), '123');
    assert.equal(out.b.data.toString(), hundred.toString());
    assert.equal(out.c.toString(), '456');
  });
});
