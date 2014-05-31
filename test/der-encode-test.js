var assert = require('assert');
var asn1 = require('..');

var Buffer = require('buffer').Buffer;

describe("asn1.js DER encoder", function() {
  /*
   * Explicit value shold be wrapped with A0 | EXPLICIT tag
   * this adds two more bytes to resulting buffer.
   * */
  it("should code explicit tag as 0xA2", function() {
    var E = asn1.define('E', function() {
      this.explicit(2).octstr()
    });

    var encoded = E.encode("X", 'der');

    // <Explicit tag> <wrapped len> <str tag> <len> <payload>
    assert.equal(encoded.toString('hex'), 'a203040158');
    assert.equal(encoded.length, 5);
  })
});
