var assert = require('assert');
var util = require('util');
var Buffer = require('buffer').Buffer;

var asn1 = require('../../asn1');
var base = asn1.base;

// Import DER constants
var der = asn1.constants.der;

function DEREncoder(entity) {
  this.enc = 'der';
  this.name = entity.name;
  this.entity = entity;

  // Construct base tree
  this.tree = new DERNode();
  this.tree._init(entity.body);
};
module.exports = DEREncoder;

DEREncoder.prototype.encode = function encode(data) {
  return this.tree._encode(data).join();
};

// Tree methods

function DERNode(parent) {
  base.Node.call(this, 'der', parent);
}
util.inherits(DERNode, base.Node);

DERNode.prototype._encodeComposite = function encodeComposite(tag,
                                                              primitive,
                                                              content) {
  var encodedTag = encodeTag(tag, primitive);

  // Short form
  if (content.length < 0x80) {
    var header = new Buffer(2);
    header[0] = encodedTag;
    header[1] = content.length;
    return new base.EncoderBuffer([ header, content ]);
  }

  // Long form
  // Count octets required to store length
  var lenOctets = 1;
  for (var i = content.length; i >= 0x100; i >>= 8)
    lenOctets++;

  var header = new Buffer(1 + 1 + lenOctets);
  header[0] = encodedTag;
  header[1] = 0x80 | lenOctets;

  for (var i = 1 + lenOctets, j = content.length; j > 0; i--, j >>= 8)
    header[i] = j & 0xff;

  return new base.EncoderBuffer([ header, content ]);
};

DERNode.prototype._encodeStr = function encodeStr(str, tag) {
  if (tag === 'octstr')
    return new base.EncoderBuffer(str);

  // TODO(indunty): support first octet
  else if (tag === 'bitstr')
    return new base.EncoderBuffer([ 0, str ]);
};

DERNode.prototype._encodeObjid = function encodeObjid(id, values, relative) {
  if (typeof id === 'string') {
    assert(values, 'string objid given, but no values map found');
    assert(values.hasOwnProperty(id), 'objid not found in values map');
    id = values[id].split(/\s+/g);
    for (var i = 0; i < id.length; i++)
      id[i] |= 0;
  }

  assert(Array.isArray(id));
  if (!relative) {
    assert(id[1] < 40, 'Second objid identifier OOB');
    id.splice(0, 2, id[0] * 40 + id[1]);
  }

  // Count number of octets
  var size = 0;
  for (var i = 0; i < id.length; i++) {
    var ident = id[i];
    for (size++; ident >= 0x80; ident >>= 7)
      size++;
  }

  var objid = new Buffer(size);
  var offset = objid.length - 1;
  for (var i = id.length - 1; i >= 0; i--) {
    var ident = id[i];
    objid[offset--] = ident & 0x7f;
    while ((ident >>= 7) > 0)
      objid[offset--] = 0x80 | (ident & 0x7f);
  }

  return new base.EncoderBuffer(objid);
};

function two(num) {
  if (num <= 10)
    return '0' + num;
  else
    return num;
}

DERNode.prototype._encodeTime = function encodeTime(time, tag) {
  var str;

  // TODO(indutny): verify in spec
  if (tag === 'gentime') {
    var date = new Date(time);

    str = [
      date.getFullYear(),
      two(date.getUTCMonth() + 1),
      two(date.getUTCDate()),
      two(date.getUTCHours()),
      two(date.getUTCMinutes()),
      two(date.getUTCSeconds()),
      'Z'
    ].join('');
  } else {
    assert(0, tag + ' time is not supported yet');
  }

  return this._encodeStr(str, 'octstr');
};

DERNode.prototype._encodeNull = function encodeNull() {
  return new base.EncoderBuffer('');
};

DERNode.prototype._encodeInt = function encodeInt(num, values) {
  if (typeof num === 'string') {
    assert(values, 'String int or enum given, but no values map');
    assert(values.hasOwnProperty(num), 'Values map doesn\'t contain number');
    num = values[num];
  }

  var size = 1;
  for (var i = num; i >= 0x100; i >>= 8)
    size++;

  var out = new Buffer(size);
  for (var i = out.length - 1; i >= 0; i--) {
    out[i] = num & 0xff;
    num >>= 8;
  }

  return new base.EncoderBuffer(out);
};

DERNode.prototype._encodeBool = function encodeBool(value) {
  return new base.EncoderBuffer(value ? 0xff : 0);
};

DERNode.prototype._use = function use(encoder, data) {
  return encoder.encode(data, 'der');
};

// Utility methods

function encodeTag(tag, primitive, cls) {
  var res;

  if (tag === 'seqof')
    tag = 'seq';
  else if (tag === 'setof')
    tag = 'set';

  if (der.tagByName.hasOwnProperty(tag))
    res = der.tagByName[tag];
  else if (typeof tag === 'number' && (tag | 0) === tag)
    res = tag;
  else
    throw new Error('Unknown tag: ' + tag);

  assert(res < 0x1f, 'Multi-octet tag encoding unsupported');

  if (primitive)
    res |= 0x20;

  res |= der.tagClassByName[cls || 'universal'];

  return res;
}
