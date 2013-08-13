{ Crypto } = require '../../lib/bitcoinjs-lib.js'
{ util: { randomBytes }, charenc: { UTF8 } } = Crypto
{ parse_pubkey, parse_key_string, random_privkey } = require '../../lib/bitcoin/index.coffee'
{ navto, format_url, render, parse_query, iferr, error_displayer } = require '../lib/util.coffee'
{ format_locals } = require './lib/util.coffee'
{ handshake_listen } = require './lib/networking.coffee'
sign_message = require '../sign-message.coffee'
new_view = require './views/new.jade'
invite_view = require './views/dialogs/invite.jade'

BASE = $('base').attr('href') + 'tx.html#'

# Read and validate query params 
{ trent } = parse_query()

if trent? and not (try parse_pubkey trent)
  trent = null

# Render view
render el = $ new_view format_locals { bob_priv: random_privkey(), trent }

display_error = error_displayer el

# Handle form submission
el.find('form').submit (e) ->
  e.preventDefault()
  try
    { pub: bob, priv: bob_priv } = parse_key_string el.find('input[name=bob]').val()
    trent = parse_pubkey el.find('input[name=trent]').val()
    terms = UTF8.stringToBytes switch
      when val = el.find('textarea:visible[name=terms]').val().trim() then val
      else throw new Error 'mot implemented'
    exchange { bob, bob_priv, trent, terms }
  catch err then display_error err

# Exchange keys with other party
exchange = ({ bob, bob_priv, trent, terms }) ->
  # The initial channel to send the pubkey/signature is just a random string
  # that's sent along with the URL
  channel = randomBytes 15
  
  # Start listening for handshake replies on the random channel
  unlisten = handshake_listen channel, { bob, trent, terms }, iferr display_error, ({ alice, proof }) ->
    navto 'tx.html', { alice, trent, bob: (bob_priv ? bob), terms, proof, _is_new: true }

  # Sign message (with known private key, or with dialog asking user to do this
  # locally)
  sign_message (bob_priv ? bob), terms, iferr display_error, (sig) ->

    # Construct the invitation URL with the public keys, terms, signature and
    # random channel name
    alice_url = format_url 'join.html', { alice: bob, trent, terms, proof: sig, channel }

    # Finally, display the dialog instructing the user to share the URL with
    # the other party
    dialog = $ invite_view { alice_url }
    dialog.on 'hidden', ->
      unlisten()
      dialog.remove()
    dialog.modal()

