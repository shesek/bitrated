{ Crypto, convert: { bytesToHex } } = require 'bitcoinjs-lib'
{ util: { randomBytes }, charenc: { UTF8 } } = Crypto
{ sha256, triple_sha256 } = require '../../lib/bitcoin/index.coffee'
{ navto, format_url, render, parse_query, iferr, error_displayer } = require '../lib/util.coffee'
{ format_locals, build_tx_args } = require './lib/util.coffee'
{ handshake_listen } = require './lib/networking.coffee'
{ load_user } = require '../lib/user.coffee'
Key = require '../../lib/bitcoin/key.coffee'
sign_message = require '../sign-message.coffee'
new_view = require './views/new.jade'
invite_view = require './views/dialogs/invite.jade'

BASE = $('base').attr('href') + 'tx.html#'

# Read and validate query params 
{ trent } = parse_query()
trent = Key.from_pubkey trent if trent?

# Render view
render el = $ new_view format_locals bob: Key.random(), trent: trent

display_error = error_displayer el

# Display arbitrator info on request
arb_info = el.find('.arbitrator-info')
arb_info.find('button').click ->
  try trent = Key.from_pubkey el.find('input[name=trent]').val()
  catch err then return display_error err

  check_button = $(this).addClass('active').attr('disabled', true)
  pubkey_hash = triple_sha256 trent.pub
  load_user pubkey_hash, (err, user) ->
    check_button.removeClass('active').attr('disabled', false)
    return display_error err if err?
    if user?
      arb_info.addClass('loaded').find('.username').html "<a href='/u/#{user.username}'>#{user.username}</a>"
    else arb_info.addClass('not-found')

el.find('input[name=trent]').on('keyup change', ->
  arb_info
    .removeClass('loaded not-found')
    # Strings shorter than 15 (maximum username length) are considered usernames,
    # in which case the button shouldn't be displayed.
    .css('display', if @value.length<=15 then 'none' else 'block')
).change() # trigger it once to decide if the button should be displayed initially

# Handle form submission
form = el.find('form').submit (e) ->
  e.preventDefault()
  try
    bob = Key.from_string el.find('input[name=bob]').val()
    get_trent_pubkey iferr display_error, (trent) ->
      get_terms form, iferr display_error, (terms) ->
        exchange { bob, trent, terms }
  catch err then display_error err

# Advanced options
el.find('a[href="#advanced"]').click (e) ->
  e.preventDefault()
  el.find('.keys-advanced').toggle 'slow'

# Get the arbitrator public key
get_trent_pubkey = (cb) ->
  trent_str = el.find('input[name=trent]').val()
  # Strings longer than 15 (maximum username length) are considered public keys
  if trent_str.length > 15
    try cb null, Key.from_pubkey trent_str
    catch err then cb err
  else
    load_user trent_str, iferr cb, (user) ->
      return cb new Error 'Arbitrator not found.' unless user?
      cb null, Key.from_pubkey user.pubkey

# Get the provided terms from text, file or hash
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
    when hash = form.find('input:visible[name=terms_hash]').val()?.trim()
      cb null, format_hash_terms hash
    else
      throw new Error 'Missing terms'

format_hash_terms = (hash) -> UTF8.stringToBytes """
  I have a copy of the file that hashes (with SHA256) to #{hash},
  and I fully agree with its contents.
"""

# Exchange keys with other party
exchange = ({ bob, trent, terms }) ->
  # The initial channel to send the pubkey/signature is just a random string
  # that's sent along with the URL
  channel = randomBytes 15
  
  # Sign message (with known private key, or with dialog asking user to do this
  # locally)
  sign_message bob, terms, iferr display_error, (sig) ->

    # Construct the invitation URL with the public keys, terms, signature and
    # random channel name. Bob and Alice are reversed here, as the current
    # party is the other party for the receiver.
    alice_url = format_url 'join.html', build_tx_args { alice: bob, trent, terms, proof: sig, channel }

    # Display the dialog instructing the user to share the URL with
    # the other party
    dialog = $ invite_view { alice_url }
    dialog.on 'hidden', ->
      unlisten()
      dialog.remove()
    dialog.modal backdrop: 'static'

    # Start listening for handshake replies on the random channel
    unlisten = handshake_listen channel, { bob, trent, terms }, iferr display_error, ({ alice, proof }) ->
      navto 'tx.html', build_tx_args { bob, alice, trent, terms, proof, _is_new: true }, true
