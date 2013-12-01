var assert = require('assert');
var Buffer = require('buffer').Buffer;

function DecoderBuffer(base) {
  assert(Buffer.isBuffer(base));

  this.base = base;
  this.offset = 0;
  this.length = base.length;
}
module.exports = DecoderBuffer;

DecoderBuffer.prototype.save = function save() {
  return { offset: this.offset };
};

DecoderBuffer.prototype.restore = function restore(save) {
  // Return skipped data
  var res = new DecoderBuffer(this.base);
  res.offset = save.offset;
  res.length = this.offset;

  this.offset = save.offset;

  return res;
};

DecoderBuffer.prototype.isEmpty = function isEmpty() {
  return this.offset === this.length;
};

DecoderBuffer.prototype.readUInt8 = function readUInt8() {
  assert(this.offset + 1 <= this.length);
  return this.base.readUInt8(this.offset++, true);
}

DecoderBuffer.prototype.skip = function skip(bytes) {
  assert(this.offset + bytes <= this.length);
  var res = new DecoderBuffer(this.base);
  res.offset = this.offset;
  res.length = this.offset + bytes;
  this.offset += bytes;
  return res;
}

DecoderBuffer.prototype.raw = function raw() {
  return this.base.slice(this.offset, this.length);
}
