var assert = require('assert');

// Supported tags
var tags = [
  'seq', 'seqof', 'octstr', 'bitstr', 'objid',
  'gentime', 'utctime', 'null_', 'enum', 'int'
];

// Public methods list
var methods = [
  'key', 'obj', 'use', 'optional', 'explicit', 'implicit', 'def', 'choice'
].concat(tags);

// Overrided methods list
var overrided = [
  '_peekTag', '_execTag', '_execUse',
  '_execStr', '_execObjid', '_execTime', '_execNull', '_execInt', '_execBool',
  '_execOf'
];

function Node(enc, type, parent) {
  var state = {};
  this._baseState = state;

  state.enc = enc;
  state.type = type;

  state.parent = parent || null;
  state.children = null;

  // State
  state.tag = null;
  state.args = null;
  state.choice = null;
  state.optional = false;
  state.any = false;
  state.obj = false;
  state.use = null;
  state.key = null;
  state['default'] = null;
  state.explicit = null;
  state.implicit = null;

  // Should create new instance on each method
  if (!state.parent) {
    state.children = [];
    this._wrap();
  }
}
module.exports = Node;

Node.prototype._wrap = function wrap() {
  var state = this._baseState;
  methods.forEach(function(method) {
    this[method] = function _wrappedMethod() {
      var clone = new this.constructor(this);
      state.children.push(clone);
      return clone[method].apply(clone, arguments);
    };
  }, this);
};

Node.prototype._init = function init(body) {
  var state = this._baseState;

  assert(state.parent === null);
  body.call(this);

  // Filter children
  state.children = state.children.filter(function(child) {
    return child._baseState.parent === this;
  }, this);
  assert.equal(state.children.length, 1, 'Root node can have only one child');
};

Node.prototype._useArgs = function useArgs(args) {
  var state = this._baseState;

  // Filter children and args
  var children = args.filter(function(arg) {
    return arg instanceof this.constructor;
  }, this);
  args = args.filter(function(arg) {
    return !(arg instanceof this.constructor);
  }, this);

  if (children.length !== 0) {
    assert(state.children === null);
    state.children = children;

    // Replace parent to maintain backward link
    children.forEach(function(child) {
      child._baseState.parent = this;
    }, this);
  }
  if (args.length !== 0) {
    assert(state.args === null);
    state.args = args;
  }
};

// Execute node
Node.prototype._exec = function exec(input, obj) {
  var state = this._baseState;

  // Exec root node
  if (state.parent === null)
    return state.children[0]._exec(input);

  var result = state['default'];
  var present = true;

  // Check if tag is there
  if (state.optional) {
    present = this._peekTag(
      input,
      state.explicit !== null ? state.explicit :
          state.implicit !== null ? state.implicit :
              state.tag || 0
    );
  }

  // Push object on stack
  if (state.obj && present) {
    var prevObj = obj;
    obj = {};
  }

  if (present) {
    // Unwrap explicit values
    if (state.explicit !== null)
      input = this._execTag(input, state.explicit);

    // Unwrap implicit and normal values
    if (state.use === null && !state.any && state.choice === null) {
      input = this._execTag(
        input,
        state.implicit !== null ? state.implicit : state.tag,
        state.any
      );
    }

    // Select proper method for tag
    if (state.any)
      result = input.raw();
    if (state.choice !== null)
      result = this._execChoice(input, obj);
    else
      result = this._execByTag(state.tag, input);

    // Execute children
    if (!state.any && state.choice === null && state.children !== null) {
      state.children.forEach(function execChildren(child) {
        child._exec(input, obj);
      });
    }
  }

  // Pop object
  if (state.obj && present) {
    result = obj;
    obj = prevObj;
  }

  // Set key
  if (state.key !== null)
    obj[state.key] = result;

  return result;
};

Node.prototype._execChoice = function execChoice(input, obj) {
  var state = this._baseState;
  var result = null;
  var match = false;

  Object.keys(state.choice).some(function(key) {
    var save = input.save();
    var node = state.choice[key];
    try {
      result = node._exec(input, obj);
      match = true;
    } catch (e) {
      input.restore(save);
      return false;
    }
    return true;
  }, this);

  assert(match, 'Choice not matched');
  return result;
};

Node.prototype._execByTag = function execByTag(tag, input) {
  var state = this._baseState;

  if (tag === 'seq' || tag === 'set')
    return null;
  if (tag === 'seqof' || tag === 'setof')
    return this._execOf(input, tag, state.args[0]);
  else if (tag === 'octstr' || tag === 'bitstr')
    return this._execStr(input, tag);
  else if (tag === 'objid' && state.args)
    return this._execObjid(input, state.args[0], state.args[1]);
  else if (tag === 'objid')
    return this._execObjid(input, null, null);
  else if (tag === 'gentime')
    return this._execTime(input, tag);
  else if (tag === 'null_')
    return this._execNull(input);
  else if (tag === 'bool')
    return this._execBool(input);
  else if (tag === 'int' || tag === 'enum')
    return this._execInt(input, state.args && state.args[0]);
  else if (state.use !== null)
    return this._execUse(input, state.use);
  else
    assert(false, 'unknown tag: ' + tag);

  return null;
};

// Overrided methods
overrided.forEach(function(method) {
  Node.prototype[method] = function _overrided() {
    var state = this._baseState;
    throw new Error(method + ' not implemented for encoding: ' + state.enc);
  };
});

// Public methods

tags.forEach(function(tag) {
  Node.prototype[tag] = function _tagMethod() {
    var state = this._baseState;
    var args = Array.prototype.slice.call(arguments);

    assert(state.tag === null);
    state.tag = tag;

    this._useArgs(args);

    return this;
  };
});

Node.prototype.use = function use(item) {
  var state = this._baseState;

  assert(state.use === null);
  state.use = item;

  return this;
};

Node.prototype.optional = function optional() {
  var state = this._baseState;

  state.optional = true;

  return this;
};

Node.prototype.def = function def(val) {
  var state = this._baseState;

  assert(state['default'] === null);
  state['default'] = val;
  state.optional = true;

  return this;
};

Node.prototype.explicit = function explicit(num) {
  var state = this._baseState;

  assert(state.explicit === null && state.implicit === null);
  state.explicit = num;

  return this;
};

Node.prototype.implicit = function implicit(num) {
  var state = this._baseState;

  assert(state.explicit === null && state.implicit === null);
  state.implicit = num;

  return this;
};

Node.prototype.obj = function obj() {
  var state = this._baseState;
  var args = Array.prototype.slice.call(arguments);

  state.obj = true;

  if (args.length !== 0)
    this._useArgs(args);

  return this;
};

Node.prototype.key = function key(key) {
  var state = this._baseState;

  assert(state.key === null);
  state.key = key;

  return this;
};

Node.prototype.any = function any() {
  var state = this._baseState;

  state.any = true;

  return this;
};

Node.prototype.choice = function choice(obj) {
  var state = this._baseState;

  assert(state.choice === null);
  state.choice = obj;
  this._useArgs(Object.keys(obj).map(function(key) {
    return obj[key];
  }));

  return this;
};
