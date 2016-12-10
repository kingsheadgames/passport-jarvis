/**
 * Module dependencies.
 */
var passport = require('passport');
var util = require('util');
var BadRequestError = require('./errors/badrequesterror');

/**
 * `Strategy` constructor.
 * See local strategy. This is a port of that one
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('jarvis authentication strategy requires a verify function');
  
  this._uuidField    = options.uuidField    || 'uuid';
  this._idfaField    = options.idfaField    || 'idfa';
  this._aosAdIdField = options.aosAdIdField || 'aosAdId';
  this._gcidField    = options.gcidField    || 'gcid';
  this._fbidField    = options.fbidField    || 'fbid';
  this._gpidField    = options.gpidField    || 'gpid';
  this._deviceField  = options.deviceField  || 'device';
  this._localeField  = options.localeField  || 'locale';
  this._msdkField    = options.msdkField    || 'msdk';
  this._matIdField   = options.matIdField   || 'matId';

  passport.Strategy.call(this);
  this.name = 'jarvis';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  
  var uuid    = req.body[this._uuidField];
  var idfa    = req.body[this._idfaField];
  var aosAdId = req.body[this._aosAdIdField];
  var gcid    = req.body[this._gcidField];
  var fbid    = req.body[this._fbidField];
  var gpid    = req.body[this._gpidField];
  var device  = req.body[this._deviceField];
  var locale  = req.body[this._localeField];
  var msdk    = req.body[this._msdkField];
  var matId   = req.body[this._matIdField];

  if (!uuid) {
    return this.fail(new BadRequestError(options.badRequestMessage || 'Missing UUID'));
  }
  
  var params = {
    uuid: uuid,
    idfa: idfa,
    aosAdId: aosAdId,
    gcid: gcid,
    fbid: fbid,
    gpid: gpid,
    device: device,
    locale: locale,
    msdk: msdk,
    matId: matId
  };

  var self = this;
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }
  
  if (self._passReqToCallback) {
    this._verify(req, params, options, verified);
  } else {
    this._verify(params, options, verified);
  }
  
  function lookup(obj, field) {
    if (!obj) { return null; }
    var chain = field.split(']').join('').split('[');
    for (var i = 0, len = chain.length; i < len; i++) {
      var prop = obj[chain[i]];
      if (typeof(prop) === 'undefined') { return null; }
      if (typeof(prop) !== 'object') { return prop; }
      obj = prop;
    }
    return null;
  }
};


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
