{ Crypto } = require '../../lib/bitcoinjs-lib.js'
{ util: { bytesToHex, bytesToBase64 }, charenc: { UTF8 } } = Crypto
{ get_address, ADDR_PRIV } = require '../../lib/bitcoin/index.coffee'

# Transform tx data to human readable format
format_locals = (data) ->
  data[k] = bytesToHex data[k] for k in ['bob', 'alice', 'trent'] when data[k]?
  data.bob_priv = get_address data.bob_priv, ADDR_PRIV if data.bob_priv?
  data.terms = UTF8.bytesToString data.terms if data.terms?
  data.proof = bytesToBase64 data.proof if data.proof?
  data

module.exports = {
  format_locals
}
