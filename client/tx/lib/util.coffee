{ Crypto, convert: { bytesToHex, bytesToBase64 } } = require 'bitcoinjs-lib'
{ UTF8 } = Crypto.charenc
{ get_address, ADDR_PRIV } = require '../../../lib/bitcoin/index.coffee'
{ load_user } = require '../../lib/user.coffee'
{ iferr } = require '../../../lib/util.coffee'
Key = require '../../../lib/bitcoin/key.coffee'

# Transform tx data to human readable format
format_locals = (data) ->
  data.bob_priv = get_address data.bob.priv, ADDR_PRIV if data.bob?.priv?
  data[k] = bytesToHex data[k].pub for k in ['bob', 'alice' ] when data[k]?
  data.trent = bytesToHex data.trent.pub if data.trent?.pub?
  data.terms = UTF8.bytesToString data.terms if data.terms?
  data.proof = bytesToBase64 data.proof if data.proof?
  data


# Build the query arguments for the transaction page
#
# prefer_privkey determines if Bob's public key should
# be used when available.
build_tx_args = (args, prefer_privkey) ->
  args[k] = args[k].pub for k in [ 'alice', 'trent' ] when args[k]?.pub?
  if args.bob?
    if prefer_privkey and args.bob.priv?
      args.bob_priv = args.bob.priv
      delete args.bob
    else args.bob = args.bob.pub
  args

# Get the arbitrator public key as Key object
#
# Either from a username, pubkey hex string or existing Key object
get_trent_pubkey = (trent, cb) ->
  # Just return Key objects as-is
  if trent instanceof Key then cb null, trent
  # Strings longer than 15 (maximum username length) are considered public keys
  else if trent.length > 15
    try cb null, Key.from_pubkey trent
    catch err then cb err
  # Shorter strings are usernames, load it
  else
    load_user trent, iferr cb, (user) ->
      return cb new Error 'Arbitrator not found.' unless user?
      cb null, Key.from_pubkey user.pubkey

module.exports = { format_locals, build_tx_args, get_trent_pubkey }
