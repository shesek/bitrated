{ random_privkey } = require './bitcoin.coffee'
{ Bitcoin, Crypto } = require '../lib/bitcoinjs-lib.js'
{ util: { bytesToBase64, base64ToBytes, bytesToHex, hexToBytes }, charenc: { UTF8 } } = Crypto
{ get_address, ADDR_PRIV } = require './bitcoin.coffee'

form = $ 'form.arbitrate'

# Set random private key
form.find('input[name=trent]').val get_address random_privkey(), ADDR_PRIV

form.find('input[name=register]').change -> form.find('.register-fields').toggle('slow')

form.submit (e) ->
  e.preventDefault()


