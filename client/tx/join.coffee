{ create_multisig } = require '../../lib/bitcoin/index.coffee'
{ iferr, error_displayer, parse_query, navto, render, click_to_select } = require '../lib/util.coffee'
{ format_locals, build_tx_args, get_trent_pubkey } = require './lib/util.coffee'
{ handshake_reply } = require './lib/networking.coffee'
{ gen_key } = require './lib/encryption.coffee'
{ load_user } = require '../lib/user.coffee'
{ triple_sha256 } = require '../../lib/bitcoin/index.coffee'
Key = require '../../lib/bitcoin/key.coffee'
sign_message = require '../sign-message.coffee'
view = require './views/join.jade'

ACK_TIMEOUT = 30000 # 30 seconds

display_error = error_displayer $ '.content'

# Read and validate query params
{ alice, trent, terms, proof, tsecret } = parse_query()

try
  unless tsecret?
    # Message for old links - can be removed a few days after the new version
    # is out
    throw new Error "You received an old invitation link that is no longer supported.
                     Please ask the other party to reload the page and generate a new one."

  for key, val of { alice, trent, terms, proof, tsecret } when not val
    throw new Error "Missing argument: #{ key }"

  alice = Key.from_pubkey alice
  trent = Key.from_pubkey trent if Array.isArray trent

  unless alice.verify_sig terms, proof
    throw new Error 'Invalid signature provided by other party'

catch err then return display_error err

# Render the view
render el = $ view format_locals {
  alice, trent, terms, proof
  bob: Key.random()
}
do click_to_select

# Spinner helpers
button = el.find 'form button[type=submit]'
start_spinner = -> button.attr('disabled', true).addClass('active')
stop_spinner =  -> button.attr('disabled', false).removeClass('active')

# Make display_error stop the spinner in addition to showing the error
display_error = do (display_error) -> (err) ->
  stop_spinner?()
  display_error err

# Handle form submission
el.find('form').submit (e) ->
  e.preventDefault()

  do start_spinner

  # Parse user public/private key
  try bob = Key.from_string el.find('input[name=bob]').val()
  catch err
    el.find('input[name=bob]').focus()
    return display_error err

  get_trent_pubkey trent, iferr display_error, (trent) ->
    { script } = create_multisig [ bob.pub, alice.pub, trent.pub ]

    # Generate a new shared secret for future communication,
    # instead of the old temporary one
    gen_key iferr display_error, (new_secret) ->
      # Sign message (with known private key, or with dialog asking user to do this
      # locally)
      sign_message bob, terms, iferr display_error, (sig) ->
        ack_timer = setTimeout (->
          display_error 'Handshake verification response timed out. The other party might have closed the page.'
        ), ACK_TIMEOUT
        # Reply to the initating party - over the temp channel/secret, with the
        # current user's pubkey/signature, final multisig script and the new
        # shared secret
        handshake_reply tsecret, { pub: bob.pub, proof: sig, script, new_secret }, (err) ->
          clearTimeout ack_timer
          return display_error err if err?
          navto 'tx.html', build_tx_args { bob, alice, trent, terms, proof, secret: new_secret, _is_new: true }, true

# Advanced options
el.find('a[href="#advanced"]').click (e) ->
  e.preventDefault()
  el.find('.keys-advanced').toggle 'slow'
