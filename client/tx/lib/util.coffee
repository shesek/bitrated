{ Crypto, convert: { bytesToHex, bytesToBase64 } } = require 'bitcoinjs-lib'
{ UTF8 } = Crypto.charenc
{ get_address, ADDR_PRIV } = require '../../../lib/bitcoin/index.coffee'

# Transform tx data to human readable format
format_locals = (data) ->
  data[k] = bytesToHex data[k] for k in ['bob', 'alice', 'trent'] when data[k]?
  data.bob_priv = get_address data.bob_priv, ADDR_PRIV if data.bob_priv?
  console.log 'got data', data
  data.terms = UTF8.bytesToString data.terms if data.terms?
  data.proof = bytesToBase64 data.proof if data.proof?
  data

module.exports = {
  format_locals
}
