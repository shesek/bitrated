{ Transaction, convert: { hexToBytes, bytesToHex, bytesToBase64, base64ToBytes } } = require 'bitcoinjs-lib'
{ triple_sha256, verify_sig, create_multisig, TESTNET } = require '../../../lib/bitcoin/index.coffee'
{ decode_raw_tx } = require '../../../lib/bitcoin/tx.coffee'
Key = require '../../../lib/bitcoin/key.coffee'
io = require 'socket.io-client'

{ tx_broadcast, load_unspent } = if TESTNET then require './blockchain/testnet.coffee' \
                                            else require './blockchain/bci.coffee'

get_socket = do (socket=null) -> -> socket ||= io.connect '/'

# Join a channel and re-join if the connection is lost
#
# The returned function leaves the channel and stops persisting
persist_join = (channel) ->
  socket = get_socket()
  do join = -> socket.emit 'join', channel
  socket.on 'reconnect', join
  leave = ->
    socket.emit 'part', channel
    socket.removeListener 'reconnect', join

# Create a deterministic channel name based on the public keys and terms
get_channel = ({ bob, alice, trent, terms }) ->
  # quick & dirty way to sort byte arrays
  ordered_parties = hexToBytes [bob.pub, alice.pub].map(bytesToHex).sort().join('')
  triple_sha256 [ ordered_parties..., trent..., terms... ]

# Listen for handshake replies
# Verifies the terms signature and checks the multisig address matches,
# which also ensures all the public keys matches
handshake_listen = (channel, { bob, trent, terms }, cb) ->
  channel = bytesToBase64 channel
  socket = get_socket()
  leave = persist_join channel

  socket.once channel, hs_cb = ({ pub: alice, proof, script_hash }, ack_id) ->
    # Sends errors to callback and to the other party (via the server)
    error_cb = (err) ->
      socket.emit ack_id, err
      cb err

    alice = new Key 'pub', base64ToBytes alice
    proof = base64ToBytes proof
    { script } = create_multisig [ bob.pub, alice.pub, trent.pub ]
    expected_script_hash = bytesToBase64 triple_sha256 script.buffer

    if not alice.verify_sig terms, proof
      error_cb new Error 'Invalid terms signature'
    else if script_hash isnt expected_script_hash
      error_cb new Error 'Provided multisig script doesn\'t match'
    else
      do unlisten
      # notify success to the other party
      socket.emit ack_id, null, ->
        cb null, { alice, proof }
  unlisten = ->
    socket.removeListener channel, hs_cb
    do leave

# Send handshake reply
handshake_reply = (channel, { pub, proof, script }, cb) ->
  channel = bytesToBase64 channel
  get_socket().emit 'handshake', channel, {
    pub: bytesToBase64 pub
    proof: bytesToBase64 proof
    script_hash: bytesToBase64 triple_sha256 script.buffer
  }, cb

# Listen for incoming transaction
tx_listen = (channel, cb) ->
  channel = bytesToBase64 channel
  socket = get_socket()
  leave = persist_join channel
  socket.on channel, tx_cb = (base64tx) ->
    cb decode_raw_tx base64ToBytes base64tx
  unlisten = ->
    socket.removeListener channel, tx_cb
    do leave

# Send transaction request
tx_request = (channel, tx, cb) ->
  channel = bytesToBase64 channel
  tx = bytesToBase64 tx.serialize()
  get_socket().emit 'msg', channel, tx
  cb null

module.exports = {
  get_channel
  handshake_listen, handshake_reply
  tx_listen, tx_request
  load_unspent, tx_broadcast
}
