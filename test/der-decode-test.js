var assert = require('assert');
var asn1 = require('..');

var Buffer = require('buffer').Buffer;

describe('asn1.js DER decoder', function() {
  it('should propagate implicit tag', function() {
    var B = asn1.define('B', function() {
      this.seq().obj(
        this.key('b').octstr()
      );
    });

    var A = asn1.define('Bug', function() {
      this.seq().obj(
        this.key('a').implicit(0).use(B)
      );
    });

    var out = A.decode(new Buffer('300720050403313233', 'hex'), 'der');
    assert.equal(out.a.b.toString(), '123');
  })
});
