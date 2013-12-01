var util = require('util');

function EncoderError(path, original) {
  var message = 'Encoder error at object path: ' +
                JSON.stringify(path) +
                '\n';
  Error.call(this, message + original.message);

  this.stack = message + original.stack;
};
util.inherits(EncoderError, Error);

exports.EncoderError = EncoderError;
