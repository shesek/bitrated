{ iferr, error_displayer, success, parse_query, format_url, render } = require '../lib/util.coffee'
{ Bitcoin, Crypto: { util: { bytesToHex } } } = require '../../lib/bitcoinjs-lib.js'
{ get_address, parse_pubkey, parse_key_bytes, create_multisig, verify_sig, ADDR_PUB } = require '../../lib/bitcoin/index.coffee'
{ format_locals } = require './lib/util.coffee'
{ is_final_tx } = require '../../lib/bitcoin/tx.coffee'
{ get_channel, tx_request, tx_broadcast } = require './lib/networking.coffee'
tx_builder = require './lib/tx-builder.coffee'
sign_message = require '../sign-message.coffee'
headsup_view = require './views/dialogs/heads-up.jade'
view = require './views/multisig.jade'
qr = require 'qruri'

DEFAULT_FEE = Bitcoin.Util.parseValue '0.0001'

$root = $ '.content'
display_error = error_displayer $root

# Read and validate query params
{ bob, alice, trent, terms, proof, _is_new } = parse_query()

for key, val of { bob, alice, trent, terms, proof } when not val
  throw new Error "Missing argument: #{ key }"

for key, val of { alice, trent } when not (try parse_pubkey val)
  throw new Error "Invalid public key: #{ key }"

unless keys = (try parse_key_bytes bob)
  throw new Error 'Invalid main public/private key'

# Don't re-validate the signature when _is_new
unless _is_new or verify_sig alice, terms, proof
  throw new Error 'Invalid signature'

# @TODO: handle dispute
is_dispute = false

{ pub: bob, priv: bob_priv } = keys
bob_main = bob_priv ? bob
{ address: multisig, pubkeys, script } = create_multisig [ bob, alice, trent ]
channel = get_channel { bob, alice, trent, terms }

document.title = "#{multisig} | Bitrated"

# Render the main view
render el = $ view format_locals {
  bob, alice, trent
  bob_priv, terms, proof
  is_dispute

  pubkeys: pubkeys.map bytesToHex
  multisig, multisig_qr: qr 'bitcoin:'+multisig

  bob_address:   get_address bob, ADDR_PUB
  alice_address: get_address alice, ADDR_PUB
  trent_address: get_address trent, ADDR_PUB

  trent_url: format_url 'dispute.html', { bob, alice, trent, terms, proof }

  default_fee: Bitcoin.Util.formatValue DEFAULT_FEE
}

# When loaded for the first time, display the headsup message
# and remove the _is_new flag from the URL
if _is_new then do ->
  # bob is listed after alice and trent to ensure its not visible in the URL
  document.location.hash = format_url null, { alice, trent, bob: bob_main, terms, proof }
  dialog = $ headsup_view {
    bob_url: location.href
    has_priv: bob_priv?
  }
  dialog.on 'hidden', -> dialog.remove()
  dialog.modal()

# Initialize the transaction builder
tx_builder el.find('.tx-builder'), {
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
