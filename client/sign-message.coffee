{ Crypto, convert: { bytesToHex, base64ToBytes } } = require 'bitcoinjs-lib'
{ UTF8 } = Crypto.charenc
{ error_displayer } = require './lib/util.coffee'
{ get_address, parse_address, get_pub, ADDR_PUB, ADDR_PRIV } = require '../lib/bitcoin/index.coffee'
Key = require '../lib/bitcoin/key.coffee'
view = require './views/sign-message-dialog.jade'

# Sign terms with a public or private key
#
# If a public key is given, popup a dialog instructing the user to sign offline
sign_message_any = (key, message, cb) ->
  message = UTF8.stringToBytes message if typeof message is 'string'

  try
    if key.priv?     then cb null, key.sign_message message
    else if key.pub? then sign_message_dialog key, message, cb
    else throw new Error 'Invalid key'
  catch err then cb err

sign_message_dialog = (key, message, cb) ->
  dialog = $ view address: (get_address key.pub, ADDR_PUB), message: UTF8.bytesToString message
  display_error = error_displayer dialog.find('.errors')

  dialog.submit (e) ->
    e.preventDefault()
    try
      # Use user-provided private key
      if priv_text = dialog.find('input:visible[name=priv]').val()
        input_key = new Key 'priv', parse_address priv_text, ADDR_PRIV
        throw new Error 'Invalid private key provided' unless (bytesToHex input_key.pub) is (bytesToHex key.pub)
        cb null, input_key.sign_message message
      # Use user-provided signature
      else if sig = dialog.find('textarea:visible[name=sig]').val()
        sig = base64ToBytes sig
        throw new Error 'Invalid signature provided' unless key.verify_sig message, sig
        cb null, sig
      else throw new Error 'Please provide the private key or the signature'
      dialog.modal('hide')
    catch err then display_error err

  dialog.on 'hidden', -> do dialog.remove
  dialog.modal backdrop: 'static'

module.exports = sign_message_any
