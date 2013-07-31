qs = require 'querystring'
qr = require 'qruri'
tx_builder = require './tx-builder.coffee'
{ Bitcoin, Crypto } = require '../../lib/bitcoinjs-lib.js'
{ util: { bytesToBase64, base64ToBytes, bytesToHex, hexToBytes, randomBytes }, charenc: { UTF8 } } = Crypto
BitUtil = Bitcoin.Util
{ get_channel, tx_request, tx_broadcast, handshake_listen, handshake_reply } = require './networking.coffee'
{ is_final_tx, format_locals } = require './lib.coffee'
{ iferr, error_displayer, success, format_url, render } = require '../util.coffee'
{ get_address, parse_pubkey, create_multisig, random_privkey
  parse_key_string, parse_key_bytes, sign_message, verify_sig
  ADDR_PUB, PRIVKEY_LEN, PUBKEY_LEN } = require '../bitcoin.coffee'


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

    # Firefox decodes the hash, making the qs.parse() call decode it twice,
    # making "%2B" render as a space. Replacing this back to a plus sign
    # makes it work on Firefox.
    @[k] = base64ToBytes v.replace(/( )/g, '+') for k, v of query when v.length
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


# New transaction page
action_new = do (view = require './views/new.jade') ->
  ({ trent }) ->
    document.title = 'Start new transaction | Bitrated'
    el = $ view format_locals { bob_priv: random_privkey(), trent }
    el.find('form').submit (e) ->
      e.preventDefault()
      try
        { pub, priv } = parse_key_string el.find('input[name=bob]').val()
        trent = parse_pubkey el.find('input[name=trent]').val()
        terms = UTF8.stringToBytes el.find('textarea[name=terms]').val().trim()
        # Create a random token as the channel name
        channel = randomBytes 15
        navto { trent, channel, bob: (priv ? pub), terms }
      catch e then display_error e
    render el

# Awaiting page
action_awaiting = do (view = require './views/awaiting.jade') ->
  ({ bob, bob_main, trent, terms, channel }) ->
    document.title = "Awaiting other party... | Bitrated"
    
    $(window).on 'beforeunload', beforeunload_cb = -> 'To continue, you must wait for the other party to connect.'
    teardown.push -> $(window).off 'beforeunload', beforeunload_cb

    sign_terms bob_main, terms, iferr display_error, (signature) ->
      # Start listening for handshake replies on the random channel
      handshake_unlisten = handshake_listen channel, { bob, trent, terms }, iferr display_error, ({ alice, proof }) ->
        navto { alice, trent, bob: bob_main, terms, proof },
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

    document.title = 'Join transaction | Bitrated'
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
        navto { alice, trent, bob: (bob_priv ? bob), terms, proof },
              { proof_validated: true, display_warning: true }
    render el

# Main multi-signature page
action_multisig = do (view = require './views/multisig.jade') ->
  ({ bob, bob_priv, bob_main, alice, trent, terms, proof, is_dispute }, { display_warning }) ->
    unless bob? and alice? and trent? and terms? and proof?
      throw new Error 'Missing arguments'

    { address: multisig, pubkeys, script } = create_multisig [ bob, alice, trent ]
    channel = get_channel { bob, alice, trent, terms }

    document.title = "#{multisig} | Bitrated"
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

      bob_url:   BASE + format_url { alice, trent, bob: bob_main,  terms, proof }
      trent_url: BASE + format_url { dispute: true, bob, alice, trent, terms, proof }

      default_fee: BitUtil.formatValue DEFAULT_FEE
    }
    render el

    if display_warning
      $('.headsup').removeClass('hide').modal()

    # Initialize transaction builder
    teardown.push tx_builder el.find('.tx-builder'), {
      multisig, script, channel
      key: if is_dispute then trent else bob_main
      fees: DEFAULT_FEE
    }, iferr display_error, (signed_tx) ->
      # If its a final transaction (with two signatures), broadcast it to the
      # Bitcoin network
      if is_final_tx signed_tx
        tx_broadcast signed_tx, iferr display_error,
                                success '''Transaction succesfully broadcasted to Bitcoin network.
                                           Since multisig transaction are new and not supports by all
                                           miners, it might take some time to confirm.'''
      # Otherwise, submit an approval request
      else tx_request channel, signed_tx, iferr display_error,
                                          success '''Transaction approval request was sent to the other
                                                     parties.'''


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
