{ random_privkey } = require './bitcoin.coffee'
{ Bitcoin, Crypto } = require '../lib/bitcoinjs-lib.js'
{ util: { bytesToBase64, base64ToBytes, bytesToHex, hexToBytes }, charenc: { UTF8 } } = Crypto
{ get_address, parse_key_string, ADDR_PRIV } = require './bitcoin.coffee'
{ iferr, error_displayer } = require './util.coffee'


signup = (user, cb) ->
  user.pubkey = bytesToBase64 user.pubkey
  user.sig = bytesToBase64 user.sig
  $.post('/u', user, 'json')
    .done((res) -> cb null, res)
    .fail((res) -> cb (try JSON.parse res.responseText) or res)

sign_terms = (key, terms, cb) -> cb null, [1, 6, 7, 10, 200]

form = $ 'form.arbitrate'
display_error = error_displayer form

# Set random private key
form.find('input[name=key]').val get_address random_privkey(), ADDR_PRIV

# Handle submission
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
      document.location = '/arbitrator.html#' + bytesToBase64 (pub ? priv)

