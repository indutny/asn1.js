var assert = require('assert');
var util = require('util');

var asn1 = require('../../asn1');
var base = asn1.base;

function DERDecoder(entity) {
  this.enc = 'der';
  this.name = entity.name;
  this.entity = entity;

  // Construct base tree
  this.tree = new DERNode();
  this.tree._init(entity.body);
};
module.exports = DERDecoder;

DERDecoder.prototype.decode = function decode(data) {
  if (!(data instanceof base.DecoderBuffer))
    data = new base.DecoderBuffer(data);

  return this.tree._exec(data);
};

// Tree methods

function DERNode(parent) {
  base.Node.call(this, 'der', 'decoder', parent);
}
util.inherits(DERNode, base.Node);

DERNode.prototype._peekTag = function peekTag(buffer, tag) {
  if (buffer.isEmpty())
    return false;

  var state = buffer.save();
  var decodedTag = decodeTag(buffer);
  buffer.restore(state);

  return decodedTag.tag === tag || decodedTag.tagStr === tag;
};

DERNode.prototype._execTag = function execTag(buffer, tag, any) {
  var decodedTag = decodeTag(buffer);
  var len = decodeLen(buffer, decodedTag.primitive);

  if (!any) {
    assert(decodedTag.tag === tag ||
           decodedTag.tagStr === tag ||
           decodedTag.tagStr + 'of' === tag,
           'Failed to match tag: ' + tag);
  }

  if (decodedTag.primitive || len !== null)
    return buffer.skip(len);

  assert(0, 'Indefinite length not implemented yet');
};

DERNode.prototype._execOf = function execOf(buffer, tag, decoder) {
  var result = [];
  while (!buffer.isEmpty())
    result.push(decoder.decode(buffer, 'der'));
  return result;
};

DERNode.prototype._execStr = function execStr(buffer, tag) {
  return buffer.raw();
};

DERNode.prototype._execObjid = function execObjid(buffer, values, relative) {
  var identifiers = [];
  var ident = 0;
  while (!buffer.isEmpty()) {
    var subident = buffer.readUInt8();
    ident <<= 7;
    ident |= subident & 0x7f;
    if ((subident & 0x80) === 0) {
      identifiers.push(ident);
      ident = 0;
    }
  }
  if (subident & 0x80)
    identifiers.push(ident);

  var first = (identifiers[0] / 40) | 0;
  var second = identifiers[0] % 40;

  if (relative)
    result = identifiers;
  else
    result = [first, second].concat(identifiers.slice(1));

  if (values)
    result = values[result.join(' ')];

  return result;
};

DERNode.prototype._execTime = function execTime(buffer, tag) {
  assert.equal(tag, 'gentime');

  var str = buffer.raw().toString();
  var year = str.slice(0, 4) | 0;
  var mon = str.slice(4, 6) | 0;
  var day = str.slice(6, 8) | 0;
  var hour = str.slice(8, 10) | 0;
  var min = str.slice(10, 12) | 0;
  var sec = str.slice(12, 14) | 0;

  return Date.UTC(year, mon - 1, day, hour, min, sec, 0);
};

DERNode.prototype._execNull = function execNull(buffer) {
  return null;
};

DERNode.prototype._execBool = function execBool(buffer) {
  return buffer.readUInt8() !== 0;
};

DERNode.prototype._execInt = function execInt(buffer, values) {
  var res = 0;
  while (!buffer.isEmpty()) {
    res <<= 8;
    res |= buffer.readUInt8();
  }

  if (values)
    res = values[res];
  return res;
};

DERNode.prototype._execUse = function execUse(buffer, decoder) {
  return decoder.decode(buffer, 'der');
};

// Utility methods

var tagClasses = {
  0: 'universal',
  1: 'application',
  2: 'context',
  3: 'private'
};

var tags = {
  0x00: 'end',
  0x01: 'bool',
  0x02: 'int',
  0x03: 'bitstr',
  0x04: 'octstr',
  0x05: 'null',
  0x06: 'objid',
  0x07: 'objDesc',
  0x08: 'external',
  0x09: 'real',
  0x0a: 'enum',
  0x0b: 'embed',
  0x0c: 'utf8str',
  0x0d: 'relativeOid',
  0x10: 'seq',
  0x11: 'set',
  0x12: 'numstr',
  0x13: 'printstr',
  0x14: 't61str',
  0x15: 'videostr',
  0x16: 'ia5str',
  0x17: 'utctime',
  0x18: 'gentime',
  0x19: 'graphstr',
  0x1a: 'iso646str',
  0x1b: 'genstr',
  0x1c: 'unistr',
  0x1d: 'charstr',
  0x1e: 'bmpstr'
};

function decodeTag(buf) {
  var tag = buf.readUInt8();

  var cls = tagClasses[tag >> 6];
  var primitive = (tag & 0x20) === 0;

  // Multi-octet tag - load
  if ((tag & 0x1f) === 0x1f) {
    var oct = tag;
    tag = 0;
    while ((oct & 0x80) === 0x80) {
      oct = buf.readUInt8();
      tag <<= 7;
      tag |= oct & 0x7f;
    }
  } else {
    tag &= 0x1f;
  }
  var tagStr = tags[tag];

  return {
    cls: cls,
    primitive: primitive,
    tag: tag,
    tagStr: tagStr
  };
}

function decodeLen(buf, primitive) {
  var len = buf.readUInt8();

  // Indefinite form
  if (!primitive && len === 0x80)
    return null;

  // Definite form
  if ((len & 0x80) === 0) {
    // Short form
    return len;
  }

  // Long form
  var num = len & 0x7f;
  assert(num < 4, 'length octect is too long');
  len = 0;
  for (var i = 0; i < num; i++) {
    len <<= 8;
    len |= buf.readUInt8();
  }

  return len;
}
