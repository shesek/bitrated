{ Crypto, convert: { bytesToBase64 } } = require 'bitcoinjs-lib'
{ util: { randomBytes }, charenc: { UTF8 } } = Crypto
{ get_address, ADDR_PRIV } = require '../../lib/bitcoin/index.coffee'
Key = require '../../lib/bitcoin/key.coffee'
{ signup } = require '../lib/user.coffee'
{ navto, render, iferr, error_displayer } = require '../lib/util.coffee'
sign_message = require '../sign-message.coffee'
view = require './views/new.jade'

# Render with random private key
render form = $ view privkey: (get_address Key.random().priv, ADDR_PRIV)

# Spinner helpers
button = form.find 'form button[type=submit]'
start_spinner = -> button.attr('disabled', true).addClass('active')
stop_spinner =  -> button.attr('disabled', false).removeClass('active')

# Make display_error stop the spinner in addition to showing the error
display_error = do (display_error = error_displayer form) -> (err) ->
  do stop_spinner
  display_error err

# Handle submission
form.submit (e) ->
  e.preventDefault()
  try
    username = form.find('input[name=username]').val() or throw new Error 'Username is required'
    key = Key.from_string form.find('input[name=key]').val()
    terms = form.find('textarea[name=terms]').val() or throw new Error 'Terms are required'

    unless username.match /^[a-zA-Z0-9]{3,15}$/
      throw new Error 'Invalid username. Can only contain alphanumeric characters (a-z, A-Z, 0-9) 
                       and be between 3 and 15 characters long.'
  catch err then return display_error err

  do start_spinner

  sign_message key, terms, iferr display_error, (sig) ->
    user = { username, pubkey: key.pub, content: terms, sig }
    signup user, iferr display_error, (res) ->
      args = _is_new: true
      if key.priv?
        # Add some random data so that the key won't be visible in the URL bar
        args._ = randomBytes 160
        args.key_priv = key.priv
      else args.key = key.pub
      navto 'arbitrator.html', args

