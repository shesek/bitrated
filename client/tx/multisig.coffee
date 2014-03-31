{ Util, convert: { bytesToHex } } = require 'bitcoinjs-lib'
{ get_address, create_multisig, verify_sig, ADDR_PUB, TESTNET } = require '../../lib/bitcoin/index.coffee'
Key = require '../../lib/bitcoin/key.coffee'
{ iferr, error_displayer, success, parse_query, format_url, render, click_to_select } = require '../lib/util.coffee'
{ format_locals, build_tx_args } = require './lib/util.coffee'
{ is_final_tx } = require '../../lib/bitcoin/tx.coffee'
{ get_channel, tx_request, tx_broadcast } = require './lib/networking.coffee'
tx_builder = require './lib/tx-builder.coffee'
sign_message = require '../sign-message.coffee'
headsup_view = require './views/dialogs/heads-up.jade'
view = require './views/multisig.jade'
qr = require 'qruri'

DEFAULT_FEE = 10000 # 0.0001 BTC

$root = $ '.content'
display_error = error_displayer $root

# Read and validate query params
{ bob, bob_priv, alice, trent, terms, proof, is_dispute, secret, _is_new } = query_args = parse_query()

try
  if bob_priv? then bob = Key.from_privkey bob_priv
  else if bob? then bob = Key.from_pubkey bob
  else throw new Error "Missing argument: bob"

  for key, val of { alice, trent, terms, proof } when not val
    throw new Error "Missing argument: #{ key }"

  alice = Key.from_pubkey alice
  trent = Key.from_pubkey trent

  # Don't re-validate the signature when _is_new
  unless _is_new or alice.verify_sig terms, proof
    throw new Error 'Invalid signature'

catch err then return display_error err

{ address: multisig, pubkeys, script } = create_multisig [ bob.pub, alice.pub, trent.pub ]

# Backward comptabillity - use the generated channel as the secret when no
# secret is provided
secret ?= get_channel { bob, alice, trent, terms }

document.title = "#{multisig} | Bitrated"

# Render the main view
render el = $ view format_locals {
  bob, alice, trent
  terms, proof
  is_dispute

  pubkeys: pubkeys.map bytesToHex
  multisig, multisig_qr: qr 'bitcoin:'+multisig, margin: 0

  bob_address:   get_address bob.pub, ADDR_PUB
  alice_address: get_address alice.pub, ADDR_PUB
  trent_address: get_address trent.pub, ADDR_PUB

  trent_url: format_url 'tx.html', build_tx_args { bob, alice, trent, terms, proof, secret, is_dispute: true }

  default_fee: Util.formatValue DEFAULT_FEE
  testnet: TESTNET
}
do click_to_select

# When loaded for the first time, display the headsup message
# and remove the _is_new flag from the URL
if _is_new then do ->
  delete query_args._is_new
  document.location.hash = format_url null, query_args
  dialog = $ headsup_view {
    bob_url: location.href
    has_priv: bob.priv?
  }
  dialog.on 'hidden', -> dialog.remove()
  dialog.modal backdrop: 'static', keyboard: false

# Advanced mode
el.find('.show-advanced').change ->
 el.find('.tx-details').toggleClass 'advanced-off advanced-on'

# Initialize the transaction builder
tx_builder el.find('.tx-builder'), {
  multisig, script, pubkeys, secret, is_dispute
  key: if is_dispute then trent else bob
}, iferr display_error, (signed_tx) ->
  # If its a final transaction (with two signatures), broadcast it to the
  # Bitcoin network
  if is_final_tx signed_tx
    txid = bytesToHex signed_tx.getHash()
    tx_broadcast signed_tx, iferr display_error,
                            success "<p>Transaction successfully broadcasted to the Bitcoin network.</p>
                                     <p><small><strong>Transaction id</strong>: #{txid}</small></p>"
  # Otherwise, submit an approval request
  else tx_request secret, signed_tx, iferr display_error,
                success '''<p>Transaction request was sent to the other parties. It will expire in two days.</p>
                           <p>Once approved, the transaction will be broadcasted to the Bitcoin network.</p>'''
