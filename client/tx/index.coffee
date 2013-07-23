qs = require 'querystring'
qr = require 'qruri'
{ Bitcoin, Crypto } = require '../../lib/bitcoinjs-lib.js'
{ util: { bytesToBase64, base64ToBytes, bytesToHex, hexToBytes, randomBytes }, charenc: { UTF8 } } = Crypto
BitUtil = Bitcoin.Util
{ get_channel, tx_request, tx_broadcast, handshake_listen, handshake_reply } = require './networking.coffee'
{ is_final_tx } = require './lib.coffee'
tx_builder = require './tx-builder.coffee'
{ iferr, error_displayer } = require '../util.coffee'
{ get_address, parse_pubkey, create_multisig, random_privkey
  parse_key_string, parse_key_bytes, sign_message, verify_sig
  ADDR_PUB, ADDR_PRIV, PRIVKEY_LEN, PUBKEY_LEN } = require '../bitcoin.coffee'


DEBUG = !!~document.location.hash.indexOf('DEBUG')
TESTNET = !!~document.location.hash.indexOf('TESTNET')
BASE = 'http://localhost:8070/tx.html#'
DEFAULT_FEE = BitUtil.parseValue '0.0001'

# Bob is always the current user, Alice is the other party,
# and Trent is the arbitrator.
#
# The bob, alice and trent variables represent the respective public keys.


$root = $ '.content'
display_error = error_displayer $root

teardown = []
route = (query, ctx) ->
  do fn for fn in teardown
  teardown = []

  try new -> # new `this` context used for initializing request data

    @[k] = base64ToBytes v for k, v of query when v.length
    @is_dispute = true if query.dispute?
    
    for k in ['alice', 'trent'] when @[k]? and not @[k] = parse_pubkey @[k]
      throw new Error "Invalid public key for #{k}: '#{@[k]}'"
    if @bob?
      unless keys = parse_key_bytes @bob
        throw new Error "Invalid public/private key: '#{@bob}'"
      { pub: @bob, priv: @bob_priv } = keys
      @bob_main = @bob_priv ? @bob

    #
    if not ctx.proof_validated and @alice? and @proof? and not verify_sig @alice, @terms, @proof
      @proof = null

    # Figure out the action from the available parameters
    action =
      unless (@bob or @alice) and @trent and @terms then action_new
      else if not @alice then action_awaiting
      else if not @bob then action_join
      else action_multisig
    action this, ctx

  catch e
    if DEBUG then throw e
    else display_error e.message

render = (el) ->
  $root.empty().append(el)
  el.find('[data-toggle=tooltip]').tooltip()
  el.find('[data-toggle=popover]').popover()

# New transaction page
action_new = do (view = require './views/new.jade') ->
  ({ trent }) ->
    document.title = 'Start new transaction | Bitrator'
    el = $ view format_locals { bob_priv: random_privkey(), trent }
    el.find('form').submit (e) ->
      e.preventDefault()
      try
        { pub, priv } = parse_key_string el.find('input[name=bob]').val()
        trent = hexToBytes el.find('input[name=trent]').val()
        terms = UTF8.stringToBytes el.find('textarea[name=terms]').val().trim()
        # Create a random token as the channel name
        channel = randomBytes 15
        navto { bob: (priv ? pub), trent, terms, channel }
      catch e then display_error e
    render el

# Awaiting page
action_awaiting = do (view = require './views/awaiting.jade') ->
  ({ bob, bob_main, trent, terms, channel }) ->
    document.title = "Awaiting other party... | Bitrator"
    
    $(window).on 'beforeunload', beforeunload_cb = -> 'To continue, you must wait for the other party to connect.'
    teardown.push -> $(window).off 'beforeunload', beforeunload_cb

    sign_terms bob_main, terms, iferr display_error, (signature) ->
      # Start listening for handshake replies on the random channel
      handshake_unlisten = handshake_listen channel, { bob, trent, terms }, iferr display_error, ({ alice, proof }) ->
        navto { bob: bob_main, alice, trent, terms, proof },
              { proof_validated: true, display_warning: true }
      render $ view
        alice_url: BASE + format_url { alice: bob, trent, terms, proof: signature, channel }
      teardown.push handshake_unlisten
 
# Join transaction
action_join = do (view = require './views/join.jade') ->
  ({ alice, trent, terms, proof, channel }) ->
    unless alice? and trent? and terms? and channel?
      throw new Error 'Missing arguments'
    unless proof?
      throw new Error 'Invalid signature provided by other party'

    document.title = 'Join transaction | Bitrator'
    el = $ view format_locals {
      alice, trent, terms, proof
      bob_priv: random_privkey()
    }
    
    el.find('form').submit (e) ->
      e.preventDefault()
      try keys = parse_key_string el.find('input[name=bob]').val()
      catch e
        el.find('input[name=bob]').focus()
        return display_error e.message
      { pub: bob, priv: bob_priv } = keys
      sign_terms (bob_priv ? bob), terms, iferr display_error, (signature) ->
        { script } = create_multisig [ bob, alice, trent ]
        handshake_reply channel, { pub: bob, proof: signature, script }
        navto { bob: (bob_priv ? bob), alice, trent, terms, proof },
              { proof_validated: true, display_warning: true }
    render el

# Main multi-signature page
action_multisig = do (view = require './views/multisig.jade') ->
  ({ bob, bob_priv, bob_main, alice, trent, terms, proof, is_dispute }, { display_warning }) ->
    unless bob? and alice? and trent? and terms? and proof?
      throw new Error 'Missing arguments'

    { address: multisig, pubkeys, script } = create_multisig [ bob, alice, trent ]
    channel = get_channel { bob, alice, trent, terms }

    document.title = "#{multisig} | Bitrator"
    el = $ view format_locals {
      bob, alice, trent
      bob_priv, terms, proof
      is_dispute, display_warning

      pubkeys: pubkeys.map bytesToHex
      multisig
      multisig_qr: qr 'bitcoin:'+multisig

      bob_address: get_address bob, ADDR_PUB
      alice_address: get_address alice, ADDR_PUB
      trent_address: get_address trent, ADDR_PUB

      bob_url:   BASE + format_url { alice, trent, terms, proof, bob: bob_main }
      trent_url: BASE + format_url { dispute: true, bob, alice, trent, terms, proof }

      default_fee: BitUtil.formatValue DEFAULT_FEE
    }
    render el

    # Initialize transaction builder
    teardown.push tx_builder el.find('.tx-builder'), {
      multisig, script, channel
      key: if is_dispute then trent else bob_main
      fees: DEFAULT_FEE
    }, iferr display_error, (signed_tx) ->
      if is_final_tx signed_tx
        tx_broadcast signed_tx, iferr display_error,
                                success '''Transaction broadcasted to Bitcoin network.
                                           It might take awhile to be included in a block.'''
      else tx_request channel, signed_tx, iferr display_error,
                                          success '''Transaction approval request was sent to the other
                                                     parties.'''

# Transform data to human readable format
format_locals = (data) ->
  data[k] = bytesToHex data[k] for k in ['bob', 'alice', 'trent'] when data[k]?
  data.bob_priv = get_address data.bob_priv, ADDR_PRIV if data.bob_priv?
  data.terms = UTF8.bytesToString data.terms if data.terms?
  data.proof = bytesToBase64 data.proof if data.proof?
  data

# Create query string for the given data, with base64 encoding
format_url = (data) ->
  is_sensitive = data.bob?.length is PRIVKEY_LEN
  query = {}
  for name, val of data when val?
    query[name] = if Array.isArray val then bytesToBase64 val \
                  else val
  (if is_sensitive then 'DO-NOT-SHARE&' else '') + \
  (if TESTNET      then 'TESTNET&'      else '') + \
  qs.stringify query

# success(message) returns a function that dispalys a success message
success = do (view = require '../views/dialog-success.jade') -> (message) -> ->
  dialog = $ view { message }
  dialog.on 'hidden', -> do dialog.remove
  dialog.modal()

# Sign terms
#
# If the private key is unknown, popup a dialog asking for the
# signature or the private key
sign_terms = (key, terms, cb) ->
  switch key.length
    when PRIVKEY_LEN
      cb null, sign_message key, terms
    when PUBKEY_LEN
      throw new Error 'Not yet supported'
    else
      throw new Error 'Invalid key'

next_ctx = null
navto = (query, ctx) ->
  next_ctx = ctx
  location.hash = format_url query
$(window).on 'hashchange', run = ->
  ctx = next_ctx
  next_ctx = null
  query = qs.parse location.hash.substr(1)
  route query, ctx or {}
do run
