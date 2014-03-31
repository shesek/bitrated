{ Crypto, convert: { bytesToHex } } = require 'bitcoinjs-lib'
{ util: { randomBytes }, charenc: { UTF8 } } = Crypto
{ sha256, triple_sha256 } = require '../../lib/bitcoin/index.coffee'
{ navto, format_url, render, parse_query, iferr, error_displayer, click_to_select } = require '../lib/util.coffee'
{ format_locals, build_tx_args, get_trent_pubkey } = require './lib/util.coffee'
{ handshake_listen } = require './lib/networking.coffee'
{ gen_key } = require './lib/encryption.coffee'
Key = require '../../lib/bitcoin/key.coffee'
sign_message = require '../sign-message.coffee'
new_view = require './views/new.jade'
invite_view = require './views/dialogs/invite.jade'

BASE = $('base').attr('href') + 'tx.html#'

# Read and parse query params
{ trent } = parse_query()
# Trent is either pubkey or username
trent = Key.from_pubkey trent if Array.isArray trent

# Render view
render el = $ new_view format_locals bob: Key.random(), trent: trent
do click_to_select

display_error = error_displayer el

# Handle form submission
form = el.find('form').submit (e) ->
  e.preventDefault()
  try
    bob = Key.from_string el.find('input[name=bob]').val()
    trent_str = el.find('input[name=trent]').val()
    get_trent_pubkey trent_str, iferr display_error, (trent) ->
      get_terms form, iferr display_error, (terms) ->
        # Pass username when inputted as a username and not as a pubkey
        trent_user = (trent_str if trent_str.length <= 15)
        exchange { bob, trent, trent_user, terms }
  catch err then display_error err

# Advanced options
el.find('a[href="#advanced"]').click (e) ->
  e.preventDefault()
  el.find('.keys-advanced').toggle 'slow'

# Get the provided terms from text or file
get_terms = (form, cb) ->
  switch
    when val = form.find('textarea:visible[name=terms]').val()?.trim()
      cb null, UTF8.stringToBytes val
    when file = form.find('input:visible[name=terms_file]')[0]?.files[0]
      reader = new FileReader
      reader.onload = ->
        hash = bytesToHex sha256 Array.apply null, reader.result
        cb null, format_hash_terms hash
      reader.readAsArrayBuffer file
    else
      throw new Error 'Missing terms'

format_hash_terms = (hash) -> UTF8.stringToBytes """
  I have a copy of the file that hashes (with SHA256) to #{hash},
  and I fully agree with its contents.
"""

# Exchange keys with other party
exchange = ({ bob, trent, trent_user, terms }) ->
  # Create a temporary secret for the handshake channel and key.
  # This is later replaced with a different permenant key
  gen_key iferr display_error, (tsecret) ->
    # Sign message (with known private key, or with dialog asking user to do this
    # locally)
    sign_message bob, terms, iferr display_error, (sig) ->
      # Construct the invitation URL with the public keys, terms, signature and secret
      # Bob and Alice are reversed here, as the current party is the other party for the receiver.
      alice_url = format_url 'join.html', build_tx_args { alice: bob, trent: (trent_user ? trent), terms, proof: sig, tsecret }

      # Display the dialog instructing the user to share the URL with
      # the other party
      dialog = $ invite_view { alice_url }
      dialog.on 'hidden', ->
        unlisten()
        dialog.remove()
      dialog.modal backdrop: 'static'

      # Start listening for handshake replies
      unlisten = handshake_listen tsecret, { bob, trent, terms }, iferr display_error, ({ alice, proof, new_secret }) ->
        navto 'tx.html', build_tx_args { bob, alice, trent, terms, proof, secret: new_secret, _is_new: true }, true
