{ Crypto } = require '../../lib/bitcoinjs-lib.js'
{ util: { randomBytes, bytesToHex }, charenc: { UTF8 } } = Crypto
{ parse_pubkey, parse_key_string, random_privkey, sha256b } = require '../../lib/bitcoin/index.coffee'
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
#$(window).error display_error

# Handle form submission
form = el.find('form').submit (e) ->
  e.preventDefault()
  try
    { pub: bob, priv: bob_priv } = parse_key_string el.find('input[name=bob]').val()
    trent = parse_pubkey el.find('input[name=trent]').val()
    get_terms form, iferr display_error, (terms) ->
      exchange { bob, bob_priv, trent, terms }
  catch err then display_error err

# Get the provided terms from text, file or hash
get_terms = (form, cb) ->
  switch
    when val = el.find('textarea:visible[name=terms]').val()?.trim()
      cb null, UTF8.stringToBytes val
    when file = form.find('input:visible[name=terms_file]')[0]?.files[0]
      reader = new FileReader
      reader.onload = ->
        hash = bytesToHex sha256b Array.apply null, reader.result
        cb null, format_hash_terms hash
      reader.readAsArrayBuffer file
    when hash = form.find('input:visible[name=terms_hash]').val()?.trim()
      cb null, format_hash_terms hash
    else
      debugger

format_hash_terms = (hash) -> UTF8.stringToBytes """
  I hereby declare that:

  - I have a copy of the file that hashes (with sha256) to #{hash}.
  - This file contains the terms of the transaction.
  - I fully agree with terms outlined in this file.
"""

# Exchange keys with other party
exchange = ({ bob, bob_priv, trent, terms }) ->
  # The initial channel to send the pubkey/signature is just a random string
  # that's sent along with the URL
  channel = randomBytes 15
  
  # Sign message (with known private key, or with dialog asking user to do this
  # locally)
  sign_message (bob_priv ? bob), terms, iferr display_error, (sig) ->

    # Construct the invitation URL with the public keys, terms, signature and
    # random channel name
    alice_url = format_url 'join.html', { alice: bob, trent, terms, proof: sig, channel }

    # Display the dialog instructing the user to share the URL with
    # the other party
    dialog = $ invite_view { alice_url }
    dialog.on 'hidden', ->
      unlisten()
      dialog.remove()
    dialog.modal()

    # Start listening for handshake replies on the random channel
    unlisten = handshake_listen channel, { bob, trent, terms }, iferr display_error, ({ alice, proof }) ->
      navto 'tx.html', { alice, trent, bob: (bob_priv ? bob), terms, proof, _is_new: true }


