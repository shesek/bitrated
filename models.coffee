{ Schema } = require 'mongoose'
timestamp = require 'mongoose-time'
require 'mongoose-pagination'

to_buff = (val) -> if val instanceof Buffer then val else new Buffer val, 'base64'
buff_getter = (key, encoding) -> -> this[key].toString encoding

TX_EXPIRY = '24h'

module.exports = (db) ->
  #
  # User model
  #
  User = db.model 'User', userSchema = Schema
    _id:     type: String, required: true, match: /^[A-Za-z0-9\-]{3,15}$/
    pubkey:  type: Buffer, required: true, set: to_buff
    content: type: String, required: true
    sig:     type: Buffer, required: true, set: to_buff
  userSchema.plugin timestamp
  userSchema.virtual('address').get -> get_address [ @pubkey... ], ADDR_PUB
  userSchema.virtual('pubkey_str').get buff_getter 'pubkey', 'hex'
  userSchema.virtual('sig_str').get buff_getter 'pubkey', 'base64'
  #userSchema.pre 'save', (next) ->
  #  if verify_message_sig (hexToBytes @pubkey), user.content, (hexToBytes @sig)
  #    next null
  #  else next new Error 'Invalid signature provided'

  #
  # Rating model
  #
  Rating = db.model 'Rating', ratingSchema = Schema
    _user:   type: String, required: true, ref: 'User'
    _rater:  type: String, required: true, ref: 'User'
    rating:  type: Number, required: true, min: 0, max: 1
    content: type: String, required: true
  ratingSchema.plugin timestamp

  #
  # Transaction model
  #
  Transaction = db.model 'Transaction', transactionSchema = Schema
    channel:    type: Buffer, required: true, set: to_buff
    rawtx:      type: Buffer, required: true, set: to_buff
    created_at: type: Date, default: Date.now, expires: TX_EXPIRY

  { User, Rating, Transaction }
