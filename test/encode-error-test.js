var assert = require('assert');
var asn1 = require('..');

var Buffer = require('buffer').Buffer;

describe('asn1.js encode error', function() {
  function test(name, model, input, expected) {
    it('should support ' + name, function() {
      var M = asn1.define('TestModel', model);

      var error;
      assert.throws(function() {
        try {
          var encoded = M.encode(input, 'der');
        } catch (e) {
          error = e;
          throw e;
        }
      });

      assert(expected.test(error.stack),
             'Failed to match, expected: ' + expected + ' got: ' +
                 JSON.stringify(error.stack));
    });
  }

  describe('primitives', function() {
    test('int', function() {
      this.int();
    }, 'hello', /no values map/i);

    test('enum', function() {
      this.enum({ 0: 'hello', 1: 'world' });
    }, 'gosh', /contain: "gosh"/);

    test('objid', function() {
      this.objid();
    }, 1, /objid\(\) should be either array or string, got: 1/);
  });

  describe('composite', function() {
    test('shallow', function() {
      this.seq().obj(
        this.key('key').int()
      );
    }, { key: 'hello' } , /object path: "key"/i);

    test('deep and empty', function() {
      this.seq().obj(
        this.key('a').seq().obj(
          this.key('b').seq().obj(
            this.key('c').int()
          )
        )
      );
    }, { } , /object path: "a.b"/i);

    test('deep', function() {
      this.seq().obj(
        this.key('a').seq().obj(
          this.key('b').seq().obj(
            this.key('c').int()
          )
        )
      );
    }, { a: { b: { c: 'hello' } } } , /object path: "a.b.c"/i);

    test('use', function() {
      var S = asn1.define('S', function() {
        this.seq().obj(
          this.key('x').int()
        );
      });

      this.seq().obj(
        this.key('a').seq().obj(
          this.key('b').use(S)
        )
      );
    }, { a: { b: { x: 'hello' } } } , /object path: "a.b.x"/i);
  });
});
