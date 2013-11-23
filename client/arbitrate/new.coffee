{ Crypto: convert: { bytesToBase64 } } = require 'bitcoinjs-lib'
{ util: { randomBytes }, charenc: { UTF8 } } = Crypto
{ random_privkey, get_address, parse_key_string, ADDR_PRIV } = require '../../lib/bitcoin/index.coffee'
{ signup } = require '../lib/user.coffee'
{ navto, render, iferr, error_displayer } = require '../lib/util.coffee'
sign_message = require '../sign-message.coffee'
view = require './views/new.jade'

# Render with random private key
render form = $ view privkey: (get_address random_privkey(), ADDR_PRIV)

# Handle submission
display_error = error_displayer form
form.submit (e) ->
  e.preventDefault()
  try
    username = form.find('input[name=username]').val() or throw new Error 'Username is required'
    { pub, priv } = parse_key_string form.find('input[name=key]').val()
    terms = form.find('textarea[name=terms]').val() or throw new Error 'Terms are required'
    terms_ba = UTF8.stringToBytes terms

    unless username.match /^[a-zA-Z0-9]+$/
      throw new Error 'Invalid username. Can only contain alphanumeric characters (a-z, A-Z, 0-9)'
  catch e then return display_error e

  sign_message (priv ? pub), terms_ba, iferr display_error, (sig) ->
    user = { username, pubkey: pub, content: terms, sig }
    signup user, iferr display_error, (res) ->
      navto 'arbitrator.html', _: (randomBytes 160), key: (priv ? pub), _is_new: true
      # Add some random data so that the key won't be visible in the URL bar

