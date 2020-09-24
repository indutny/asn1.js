'use strict';
/* global describe it */

const assert = require('assert');
const asn1 = require('..');
const BN = require('bn.js');

const Buffer = typeof Buffer === "undefined" ? require('safer-buffer').Buffer : Buffer;

describe('asn1.js DER encoder', function() {
  /*
   * Explicit value shold be wrapped with A0 | EXPLICIT tag
   * this adds two more bytes to resulting buffer.
   * */
  it('should code explicit tag as 0xA2', function() {
    const E = asn1.define('E', function() {
      this.explicit(2).octstr()
    });

    const encoded = E.encode('X', 'der');

    // <Explicit tag> <wrapped len> <str tag> <len> <payload>
    assert.equal(encoded.toString('hex'), 'a203040158');
    assert.equal(encoded.length, 5);
  })

  function test(name, model_definition, model_value, der_expected) {
    it(name, function() {
      let Model, derActual;
      Model = asn1.define('Model', model_definition);
      derActual = Model.encode(model_value, 'der');
      assert.deepEqual(derActual, Buffer.from(der_expected,'hex'));
    });
  }

  test('should encode objDesc', function() {
    this.objDesc();
  }, Buffer.from('280'), '0703323830');

  test('should encode choice', function() {
    this.choice({
      apple: this.bool(),
    });
  }, { type: 'apple', value: true }, '0101ff');

  test('should encode implicit seqof', function() {
    const Int = asn1.define('Int', function() {
      this.int();
    });
    this.implicit(0).seqof(Int);
  }, [ 1 ], 'A003020101' );

  test('should encode explicit seqof', function() {
    const Int = asn1.define('Int', function() {
      this.int();
    });
    this.explicit(0).seqof(Int);
  }, [ 1 ], 'A0053003020101' );

  test('should encode BN(128) properly', function() {
    this.int();
  }, new BN(128), '02020080');

  test('should encode int 128 properly', function() {
    this.int();
  }, 128, '02020080');

  test('should encode 0x8011 properly', function() {
    this.int();
  }, 0x8011, '0203008011');

  test('should omit default value in DER', function() {
    this.seq().obj(
      this.key('required').def(false).bool(),
      this.key('value').int()
    );
  }, {required: false, value: 1}, '3003020101');

  it('should encode optional and use', function() {
    const B = asn1.define('B', function() {
      this.int();
    });

    const A = asn1.define('A', function() {
      this.optional().use(B);
    });

    const out = A.encode(1, 'der');
    assert.equal(out.toString('hex'), '020101');
  });

  test('should properly encode objid with dots', function() {
    this.objid({
      '1.2.398.3.10.1.1.1.2.2': 'yes'
    });
  }, 'yes', '060a2a830e030a0101010202');

  test('should properly encode objid as array of strings', function() {
    this.objid();
  }, '1.2.398.3.10.1.1.1.2.2'.split('.'), '060a2a830e030a0101010202');

  test('should properly encode bmpstr', function() {
    this.bmpstr();
  }, 'CertificateTemplate', '1e26004300650072007400690066006900630061' +
                            '0074006500540065006d0070006c006100740065');

  test('should properly encode bmpstr with cyrillic chars', function() {
    this.bmpstr();
  }, 'Привет', '1e0c041f04400438043204350442');

  it('should encode encapsulated models', function() {
    const B = asn1.define('B', function() {
      this.seq().obj(
        this.key('nested').int()
      );
    });
    const A = asn1.define('A', function() {
      this.octstr().contains(B);
    });

    const out = A.encode({ nested: 5 }, 'der')
    assert.equal(out.toString('hex'), '04053003020105');
  });

  test('should properly encode IA5 string', function() {
    this.ia5str();
  }, 'dog and bone', '160C646F6720616E6420626F6E65');

  test('should properly encode printable string', function() {
    this.printstr();
  }, 'Brahms and Liszt', '1310427261686D7320616E64204C69737A74');

  test('should properly encode T61 string', function() {
    this.t61str();
  }, 'Oliver Twist', '140C4F6C69766572205477697374');

  test('should properly encode ISO646 string', function() {
    this.iso646str();
  }, 'septic tank', '1A0B7365707469632074616E6B');

  it('should not require encoder param', function() {
     const M = asn1.define('Model', function() {
       this.choice({
         apple: this.bool(),
       });
     });
     // Note no encoder specified, defaults to 'der'
     const encoded = M.encode({ 'type': 'apple', 'value': true });
     assert.deepEqual(encoded, Buffer.from('0101ff', 'hex'));
  });
});
