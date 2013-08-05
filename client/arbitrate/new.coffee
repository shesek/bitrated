{ Bitcoin, Crypto } = require '../../lib/bitcoinjs-lib.js'
{ bytesToBase64, randomBytes } = Crypto.util
{ random_privkey, get_address, parse_key_string, ADDR_PRIV } = require '../bitcoin.coffee'
{ signup } = require '../user.coffee'
{ format_url, render, iferr, error_displayer } = require '../util.coffee'
view = require './views/new.jade'

sign_terms = (key, terms, cb) -> cb null, [1, 6, 7, 10, 200]

# Render with random private key
render form = $ view privkey: get_address random_privkey(), ADDR_PRIV

# Handle submission
display_error = error_displayer form
form.submit (e) ->
  e.preventDefault()
  try
    username = form.find('input[name=username]').val() or throw new Error 'Username is required'
    { pub, priv } = parse_key_string form.find('input[name=key]').val()
    terms = form.find('textarea[name=terms]').val() or throw new Error 'Terms are required'

    unless username.match /^[a-zA-Z0-9]+$/
      throw new Error 'Invalid username. Can only contain alphanumeric characters (a-z, A-Z, 0-9)'
  catch e then return display_error e

  sign_terms (priv ? pub), terms, iferr display_error, (sig) ->
    user = { username, pubkey: pub, content: terms, sig }
    signup user, iferr display_error, (res) ->
      document.location = '/arbitrator.html#' + format_url _: (randomBytes 60), key: (priv ? pub)
      # Add some random data so that the key won't be visible in the URL bar

