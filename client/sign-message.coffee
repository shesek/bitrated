{ Crypto, convert: { bytesToHex, base64ToBytes } } = require 'bitcoinjs-lib'
{ UTF8 } = Crypto.charenc
{ error_displayer } = require './lib/util.coffee'
{ get_address, parse_address, get_pub
  sign_message, verify_sig
  ADDR_PUB, ADDR_PRIV, PRIVKEY_LEN, PUBKEY_LEN } = require '../lib/bitcoin/index.coffee'
view = require './views/sign-message-dialog.jade'

# Sign terms with a public or private key
#
# If a public key is given, popup a dialog instructing the user to sign offline
sign_message_any = (key, message, cb) ->
  try switch key.length
    when PRIVKEY_LEN then cb null, sign_message key, message
    when PUBKEY_LEN  then sign_message_dialog key, message, cb
    else throw new Error 'Invalid key'
  catch err then cb err

sign_message_dialog = (pub, message, cb) ->
  dialog = $ view address: (get_address pub, ADDR_PUB), message: UTF8.bytesToString message
  display_error = error_displayer dialog.find('.errors')

  dialog.submit (e) ->
    e.preventDefault()
    try
      # Use user-provided private key
      if priv_text = dialog.find('input:visible[name=priv]').val()
        priv = parse_address priv_text, ADDR_PRIV
        throw new Error 'Invalid private key provided' unless (bytesToHex get_pub priv) is (bytesToHex pub)
        cb null, sign_message priv, message
      # Use user-provided signature
      else if sig = dialog.find('textarea:visible[name=sig]').val()
        sig = base64ToBytes sig
        throw new Error 'Invalid signature provided' unless verify_sig pub, message, sig
        cb null, sig
      else throw new Error 'Please provide the private key or the signature'
      dialog.modal('hide')
    catch err then display_error err

  dialog.on 'hidden', -> do dialog.remove
  dialog.modal()

module.exports = sign_message_any
