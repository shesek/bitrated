{ Schema } = require 'mongoose'
timestamp = require 'mongoose-time'
crypto = require 'crypto'
require 'mongoose-pagination'
Key = require '../lib/bitcoin/key'
{ PUBKEY_LEN, PUBKEY_C_LEN } = require '../lib/bitcoin'

TX_EXPIRY = '24h'

to_buff = (val) -> if val instanceof Buffer then val else new Buffer val, 'base64'
buff_getter = (key, encoding) -> -> this[key].toString encoding
sha256 = (data) -> crypto.createHash('sha256').update(data).digest()
triple_sha256 = (bytes) -> sha256 sha256 sha256 bytes

module.exports = (db) ->
  #
  # User model
  #
  User = db.model 'User', userSchema = Schema
    _id:     type: String, required: true, match: /^[A-Za-z0-9\-]{3,15}$/
    pubkey:  type: Buffer, required: true, unique: true, set: to_buff
    content: type: String, required: true
    sig:     type: Buffer, required: true, set: to_buff
    pubkey_hash: type: Buffer, index: true

  userSchema.plugin timestamp
  userSchema.virtual('address').get -> get_address [ @pubkey... ], ADDR_PUB
  userSchema.virtual('pubkey_str').get buff_getter 'pubkey', 'hex'
  userSchema.virtual('sig_str').get buff_getter 'sig', 'base64'

  userSchema.pre 'save', (next) ->
    # Keep a triple-sha256 version of the pubkey for lookups
    # (allows to search for public keys on the index, without
    # revealing the public key when its not in the index)
    if @isModified 'pubkey'
      @pubkey_hash = new Buffer triple_sha256 @pubkey

    # Verify the signature matches
    if (@isModified 'content') or (@isModified 'sig')
      key = new Key 'pub', (Array.apply null, @pubkey)
      try unless key.verify_sig @content, (Array.apply null, @sig)
        return next new Error 'Invalid signature provided'
      catch err then return next err

    next null

  # Verify public key length
  userSchema.path('pubkey').validate ((value) ->
    value.length in [ PUBKEY_LEN, PUBKEY_C_LEN ]
  ), 'Invalid public key'

  { User }

  #
  # Rating model
  #
  #Rating = db.model 'Rating', ratingSchema = Schema
  #  _user:   type: String, required: true, ref: 'User'
  #  _rater:  type: String, required: true, ref: 'User'
  #  rating:  type: Number, required: true, min: 0, max: 1
  #  content: type: String, required: true
  #ratingSchema.plugin timestamp

  #
  # Transaction model
  #
  #Transaction = db.model 'Transaction', transactionSchema = Schema
  #  channel:    type: Buffer, required: true, set: to_buff
  #  rawtx:      type: Buffer, required: true, set: to_buff
  #  created_at: type: Date, default: Date.now, expires: TX_EXPIRY

  #{ User, Rating, Transaction }
