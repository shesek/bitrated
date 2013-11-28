{ Crypto, convert: { bytesToHex, bytesToBase64 } } = require 'bitcoinjs-lib'
{ UTF8 } = Crypto.charenc
{ get_address, ADDR_PRIV } = require '../../../lib/bitcoin/index.coffee'

# Transform tx data to human readable format
format_locals = (data) ->
  data.bob_priv = get_address data.bob.priv, ADDR_PRIV if data.bob?.priv?
  data[k] = bytesToHex data[k].pub for k in ['bob', 'alice', 'trent'] when data[k]?
  data.terms = UTF8.bytesToString data.terms if data.terms?
  data.proof = bytesToBase64 data.proof if data.proof?
  data


# Build the query arguments for the transaction page
#
# prefer_privkey determines if Bob's public key should
# be used when available.
build_tx_args = (args, prefer_privkey) ->
  args[k] = args[k].pub for k in [ 'alice', 'trent' ] when args[k]?
  if args.bob?
    if prefer_privkey and args.bob.priv?
      args.bob_priv = args.bob.priv
      delete args.bob
    else args.bob = args.bob.pub
  args

module.exports = {
  format_locals, build_tx_args
}
