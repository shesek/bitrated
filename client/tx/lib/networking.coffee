{ Transaction, convert: { hexToBytes, bytesToHex, bytesToBase64, base64ToBytes } } = require 'bitcoinjs-lib'
{ sha256, triple_sha256, verify_sig, create_multisig, TESTNET } = require '../../../lib/bitcoin/index.coffee'
{ decode_raw_tx } = require '../../../lib/bitcoin/tx.coffee'
{ iferr } = require '../../../lib/util.coffee'
{ encrypt_ba, decrypt_ba, encrypt_jsonba, decrypt_jsonba } = require './encryption.coffee'
Key = require '../../../lib/bitcoin/key.coffee'
io = require 'socket.io-client'

{ tx_broadcast, load_unspent } = if TESTNET then require './blockchain/testnet.coffee' \
                                            else require './blockchain/mainnet.coffee'

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
#
# NOTE: The channel is now determined based on the shared secret, making this
# obslete. This is kept for compatibility for users who don't have a shared
# secret, where the determinstic channel name is used as the shared secret
get_channel = ({ bob, alice, trent, terms }) ->
  # quick & dirty way to sort byte arrays
  ordered_parties = hexToBytes [bob.pub, alice.pub].map(bytesToHex).sort().join('')
  triple_sha256 [ ordered_parties..., trent..., terms... ]

# Listen for handshake replies
# Verifies the terms signature and checks the multisig address matches,
# which also ensures all the public keys matches
handshake_listen = (secret, { bob, trent, terms }, cb) ->
  channel = bytesToBase64 triple_sha256 secret
  socket = get_socket()
  leave = persist_join channel

  socket.once channel, hs_cb = (msg, ack_id) ->
    # Sends errors to callback and to the other party (via the server)
    error_cb = (err) ->
      socket.emit ack_id, err, -> cb err
    
    decrypt_jsonba secret, msg, iferr error_cb, (data) ->
      { pub: alice, proof, script_hash, new_secret } = data

      alice = new Key 'pub', alice
      { script } = create_multisig [ bob.pub, alice.pub, trent.pub ]
      expected_script_hash = sha256 script.buffer

      if not alice.verify_sig terms, proof
        error_cb new Error 'Invalid terms signature'
      else if (bytesToBase64 script_hash) isnt (bytesToBase64 expected_script_hash)
        error_cb new Error 'Provided multisig script doesn\'t match'
      else
        do unlisten
        # notify success to the other party
        socket.emit ack_id, null, ->
          cb null, { alice, proof, new_secret }
  unlisten = ->
    socket.removeListener channel, hs_cb
    do leave

# Send handshake reply
handshake_reply = (secret, { pub, proof, script, new_secret }, cb) ->
  channel = bytesToBase64 triple_sha256 secret
  script_hash = sha256 script.buffer
  msg = { pub, proof, script_hash, new_secret }
  encrypt_jsonba secret, msg, iferr cb, (enc) ->
    get_socket().emit 'handshake', channel, enc, cb

# Listen for incoming transaction
tx_listen = (secret, cb) ->
  channel = bytesToBase64 triple_sha256 secret
  socket = get_socket()
  leave = persist_join channel
  socket.on channel, tx_cb = (enc) ->
    decrypt_ba secret, enc, (err, rawtx) ->
      return console.error "Invalid tx request", err if err?
      cb decode_raw_tx rawtx
  unlisten = ->
    socket.removeListener channel, tx_cb
    do leave

# Send transaction request
tx_request = (secret, tx, cb) ->
  channel = bytesToBase64 triple_sha256 secret
  encrypt_ba secret, tx.serialize(), iferr cb, (enc) ->
    get_socket().emit 'msg', channel, enc
    cb null

module.exports = {
  get_channel
  handshake_listen, handshake_reply
  tx_listen, tx_request
  load_unspent, tx_broadcast
}
