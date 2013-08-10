{ sha256b, verify_sig, create_multisig } = require '../../lib/bitcoin/index.coffee'
{ decode_raw_tx } = require './lib.coffee'
{ hexToBytes, bytesToHex, bytesToBase64, base64ToBytes } = Crypto.util
{ Transaction, Util: BitUtil } = Bitcoin

triple_sha256 = (bytes) -> sha256b sha256b sha256b bytes

get_socket = do (socket=null) -> -> socket ||= require('socket.io-client').connect '/', transports: ['xhr-polling']

# Create a deterministic channel name based on the public keys and terms
get_channel = ({ bob, alice, trent, terms }) ->
  # quick & dirty way to sort byte arrays
  ordered_parties = hexToBytes [bob, alice].map(bytesToHex).sort().join('')
  triple_sha256 [ ordered_parties..., trent..., terms... ]

# Listen for handshake replies
# Verifies the terms signature and checks the multisig address matches,
# which also ensures all the public keys matches
handshake_listen = (channel, { bob, trent, terms }, cb) ->
  channel = bytesToBase64 channel
  socket = get_socket()
  socket.emit 'join', channel
  socket.once channel, hs_cb = ({ pub: alice, proof, script_hash }) ->
    alice = base64ToBytes alice
    proof = base64ToBytes proof
    { script } = create_multisig [ bob, alice, trent ]
    expected_script_hash = bytesToBase64 triple_sha256 script.buffer

    if not verify_sig alice, terms, proof
      cb new Error 'Invalid terms signature'
    else if script_hash isnt expected_script_hash
      cb new Error 'Provided multisig script doesn\'t match'
    else
      do unlisten
      cb null, { alice, proof }
  unlisten = ->
    socket.emit 'part', channel
    socket.removeListener channel, hs_cb

# Send handshake reply
handshake_reply = (channel, { pub, proof, script }) ->
  channel = bytesToBase64 channel
  get_socket().emit 'handshake', channel, {
    pub: bytesToBase64 pub
    proof: bytesToBase64 proof
    script_hash: bytesToBase64 triple_sha256 script.buffer
  }

# Listen for incoming transaction
tx_listen = (channel, cb) ->
  channel = bytesToBase64 channel
  socket = get_socket()
  socket.emit 'join', channel
  socket.on channel, tx_cb = (base64tx) ->
    # TODO load total inputs balance
    cb decode_raw_tx base64ToBytes base64tx
  unlisten = ->
    socket.emit 'part', channel
    socket.removeListener 'tx:'+channel, tx_cb

# Send transaction request
tx_request = (channel, tx, cb) ->
  channel = bytesToBase64 channel
  tx = bytesToBase64 tx.serialize()
  get_socket().emit 'msg', channel, tx
  cb null

# Send transaction to Bitcoin network using blockchain.info's pushtx
tx_broadcast = (tx, cb) ->
  tx = bytesToHex tx.serialize()
  ($.post 'https://blockchain.info/pushtx?cors=true', { tx })
    .fail((xhr, status, err) -> cb "Error from blockchain.info pushtx: #{ xhr.responseText or err }")
    .done((data) -> cb null, data)

# Load unspent inputs (from blockchain.info)
load_unspent = (address, cb) ->
  if true
    return cb null, [
      hash: bytesToBase64 (hexToBytes 'dfcbbf7ef3016c1363b488b2e46c9b632618a1d63f9f454c20547364327192c5').reverse()
      index: 1
      script: hexToBytes 'a9142889b7de9708856de79ed87c26a45356b18663d887'
      value: BitUtil.parseValue '0.1'
    ]

  xhr = $.get "http://blockchain.info/unspent?active=#{address}&cors=true"
  xhr.done (res) ->
    if res.unspent_outputs
      unspent = for { tx_hash, tx_output_n, value_hex, script } in res.unspent_outputs
        hash: bytesToBase64 hexToBytes tx_hash
        index: tx_output_n
        value: BitUtil.valueToBigInt hexToBytes value_hex
        script: script
      cb null, unspent
    else cb new Error 'Missing unspent outputs in blockchain.info response'
  xhr.fail (a...) -> cb new Error 'Cannot load data from blockchain.info'

module.exports = {
  get_channel
  handshake_listen, handshake_reply
  tx_listen, tx_request
  load_unspent, tx_broadcast
}
