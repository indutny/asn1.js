var assert = require('assert');
var asn1 = require('..');

var Buffer = require('buffer').Buffer;

describe('asn1.js models', function() {
  describe('plain use', function() {
    it('should encode submodel', function() {
      var SubModel = asn1.define('SubModel', function() {
        this.seq().obj(
          this.key('b').octstr()
        );
      });
      var Model = asn1.define('Model', function() {
        this.seq().obj(
          this.key('a').int(),
          this.key('sub').use(SubModel)
        );
      });

      var data = {a: 1, sub: {b: new Buffer("XXX")}};
      var wire = Model.encode(data, 'der');
      assert.equal(wire.toString('hex'), '300a02010130050403585858');
      var back = Model.decode(wire, 'der');
      assert.deepEqual(back, data);
    });

    it('should honour implicit tag from parent', function() {
      var SubModel = asn1.define('SubModel', function() {
        this.seq().obj(
          this.key('x').octstr()
        )
      });
      var Model = asn1.define('Model', function() {
        this.seq().obj(
          this.key('a').int(),
          this.key('sub').use(SubModel).implicit(0)
        );
      });

      var data = {a: 1, sub: {x: new Buffer("123")}};
      var wire = Model.encode(data, 'der');
      assert.equal(wire.toString('hex'), '300a020101a0050403313233');
      var back = Model.decode(wire, 'der');
      assert.deepEqual(back, data);

    });

    it('should honour explicit tag from parent', function() {
      var SubModel = asn1.define('SubModel', function() {
        this.seq().obj(
          this.key('x').octstr()
        )
      });
      var Model = asn1.define('Model', function() {
        this.seq().obj(
          this.key('a').int(),
          this.key('sub').use(SubModel).explicit(0)
        );
      });

      var data = {a: 1, sub: {x: new Buffer("123")}};
      var wire = Model.encode(data, 'der');
      assert.equal(wire.toString('hex'), '300c020101a00730050403313233');
      var back = Model.decode(wire, 'der');
      assert.deepEqual(back, data);

    });

  });
});

