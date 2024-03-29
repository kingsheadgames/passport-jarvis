/**
 * Module dependencies.
 */
var Strategy = require('./strategy');
var BadRequestError = require('./errors/badrequesterror');


/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors.
 */
exports.Strategy = Strategy;

exports.BadRequestError = BadRequestError;
