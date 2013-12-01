var assert = require('assert');
var util = require('util');

var asn1 = require('../../asn1');
var base = asn1.base;

// Import DER constants
var der = asn1.constants.der;

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

  return this.tree._decode(data);
};

// Tree methods

function DERNode(parent) {
  base.Node.call(this, 'der', parent);
}
util.inherits(DERNode, base.Node);

DERNode.prototype._peekTag = function peekTag(buffer, tag) {
  if (buffer.isEmpty())
    return false;

  var state = buffer.save();
  var decodedTag = derDecodeTag(buffer);
  buffer.restore(state);

  return decodedTag.tag === tag || decodedTag.tagStr === tag;
};

DERNode.prototype._decodeTag = function decodeTag(buffer, tag, any) {
  var decodedTag = derDecodeTag(buffer);
  var len = derDecodeLen(buffer, decodedTag.primitive);

  if (!any) {
    assert(decodedTag.tag === tag ||
           decodedTag.tagStr === tag ||
           decodedTag.tagStr + 'of' === tag,
           'Failed to match tag: ' + tag);
  }

  if (decodedTag.primitive || len !== null)
    return buffer.skip(len);

  // Indefinite length... find END tag
  var state = buffer.save();
  this._skipUntilEnd(buffer);
  return buffer.restore(state);
};

DERNode.prototype._skipUntilEnd = function skipUntilEnd(buffer) {
  while (true) {
    var tag = derDecodeTag(buffer);
    var len = derDecodeLen(buffer, tag.primitive);

    if (tag.primitive || len !== null)
      buffer.skip(len)
    else
      this._skipUntilEnd(buffer);

    if (tag.tagStr === 'end')
      break;
  }
};

DERNode.prototype._decodeList = function decodeList(buffer, tag, decoder) {
  var result = [];
  while (!buffer.isEmpty()) {
    try {
      var possibleEnd = this._peekTag(buffer, 'end');
      result.push(decoder.decode(buffer, 'der'));
    } catch (e) {
      if (possibleEnd)
        break;
    }
  }
  return result;
};

DERNode.prototype._decodeStr = function decodeStr(buffer, tag) {
  return buffer.raw();
};

DERNode.prototype._decodeObjid = function decodeObjid(buffer, values, relative) {
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

DERNode.prototype._decodeTime = function decodeTime(buffer, tag) {
  var str = buffer.raw().toString();
  if (tag === 'gentime') {
    var year = str.slice(0, 4) | 0;
    var mon = str.slice(4, 6) | 0;
    var day = str.slice(6, 8) | 0;
    var hour = str.slice(8, 10) | 0;
    var min = str.slice(10, 12) | 0;
    var sec = str.slice(12, 14) | 0;
  } else if (tag === 'utctime') {
    var year = str.slice(0, 2) | 0;
    var mon = str.slice(2, 4) | 0;
    var day = str.slice(4, 6) | 0;
    var hour = str.slice(6, 8) | 0;
    var min = str.slice(8, 10) | 0;
    var sec = str.slice(10, 12) | 0;
    if (year < 70)
      year = 2000 + year;
    else
      year = 1900 + year;
  } else {
    assert(0, 'Decoding ' + tag + ' time is not supported yet');
  }

  return Date.UTC(year, mon - 1, day, hour, min, sec, 0);
};

DERNode.prototype._decodeNull = function decodeNull(buffer) {
  return null;
};

DERNode.prototype._decodeBool = function decodeBool(buffer) {
  return buffer.readUInt8() !== 0;
};

DERNode.prototype._decodeInt = function decodeInt(buffer, values) {
  var res = 0;
  while (!buffer.isEmpty()) {
    res <<= 8;
    res |= buffer.readUInt8();
  }

  if (values)
    res = values[res];
  return res;
};

DERNode.prototype._use = function use(buffer, decoder) {
  return decoder.decode(buffer, 'der');
};

// Utility methods

function derDecodeTag(buf) {
  var tag = buf.readUInt8();

  var cls = der.tagClass[tag >> 6];
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
  var tagStr = der.tag[tag];

  return {
    cls: cls,
    primitive: primitive,
    tag: tag,
    tagStr: tagStr
  };
}

function derDecodeLen(buf, primitive) {
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
