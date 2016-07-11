var assert = require('assert');
var asn1 = require('..');
var fixtures = require('./fixtures');
var jsonEqual = fixtures.jsonEqual;

describe('asn1.js tracking', function() {
  it('should track nested offsets', () => {
    var B = asn1.define('B', function() {
      this.seq().obj(
        this.key('x').int(),
        this.key('y').int()
      );
    });

    var A = asn1.define('A', function() {
      this.seq().obj(
        this.key('a').explicit(0).use(B),
        this.key('b').use(B)
      );
    });

    var input = {
      a: { x: 1, y: 2 },
      b: { x: 3, y: 4 }
    };

    var tracked = {};

    var encoded = A.encode(input, 'der');
    var decoded = A.decode(encoded, 'der', {
      track: function(path, start, end) {
        tracked[path] = [ start, end ];
      }
    });

    jsonEqual(input, decoded);
    assert.deepEqual(tracked, {
      '': [ 0, 20 ],
      a: [ 4, 12 ],
      'a/x': [ 6, 8 ],
      'a/y': [ 9, 11 ],
       b: [ 12, 20 ],
      'b/x': [ 14, 16 ],
      'b/y': [ 17, 19 ]
    });
  });
});
