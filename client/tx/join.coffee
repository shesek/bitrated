{ parse_pubkey, parse_key_string, random_privkey, create_multisig, verify_sig } = require '../../lib/bitcoin/index.coffee'
{ iferr, error_displayer, parse_query, navto, render } = require '../lib/util.coffee'
{ format_locals } = require './lib/util.coffee'
{ handshake_reply } = require './lib/networking.coffee'
sign_message = require '../sign-message.coffee'
view = require './views/join.jade'

ACK_TIMEOUT = 30*60*1000 # 30 seconds

# Read and validate query params
{ alice, trent, terms, proof, channel } = parse_query()

for key, val of { alice, trent, terms, proof, channel } when not val
  throw new Error "Missing argument: #{ key }"

for key, val of { alice, trent } when not (try parse_pubkey val)
  throw new Error "Invalid public key: #{ key }"

unless verify_sig alice, terms, proof
  throw new Error 'Invalid signature provided by other party'

# Render the view
render el = $ view format_locals {
  alice, trent, terms, proof
  bob_priv: random_privkey()
}

button = el.find 'form button[type=submit]'
start_spinner = -> button.attr('disabled', true).addClass('active')
stop_spinner =  -> button.attr('disabled', false).removeClass('active')

# display_error also stops the spinner
display_error = do (display_error = error_displayer el) -> (err) ->
  do stop_spinner
  display_error err

# Handle form submission
el.find('form').submit (e) ->
  e.preventDefault()

  do start_spinner

  # Parse user public/private key
  try keys = parse_key_string el.find('input[name=bob]').val()
  catch err
    el.find('input[name=bob]').focus()
    return display_error err

  { pub: bob, priv: bob_priv } = keys
  { script } = create_multisig [ bob, alice, trent ]

  # Sign message (with known private key, or with dialog asking user to do this
  # locally)
  sign_message (bob_priv ? bob), terms, iferr display_error, (sig) ->
    ack_timer = setTimeout (-> display_error 'Handshake verification response timed out'), ACK_TIMEOUT
    handshake_reply channel, { pub: bob, proof: sig, script }, (err) ->
      clearTimeout ack_timer
      return display_error err if err?
      navto 'tx.html', { alice, trent, bob: (bob_priv ? bob), terms, proof, _is_new: true }
