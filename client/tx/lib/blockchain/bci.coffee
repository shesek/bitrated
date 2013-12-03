{ Util: { parseValue, bytesToNum }, convert: { bytesToHex, hexToBytes } } = require 'bitcoinjs-lib'

# Send transaction to Bitcoin network using blockchain.info's pushtx
tx_broadcast = (tx, cb) ->
  tx = bytesToHex tx.serialize()
  ($.post 'https://blockchain.info/pushtx?cors=true', { tx })
    .fail((xhr, status, err) -> cb "Error from blockchain.info pushtx: #{ xhr.responseText or err }")
    .done((data) -> cb null, data)

# Load unspent inputs (from blockchain.info)
load_unspent = (address, cb) ->
  xhr = $.get "https://blockchain.info/unspent?active=#{address}&cors=true"
  xhr.done (res) ->
    if res.unspent_outputs
      unspent = for { tx_hash, tx_output_n, value, script, confirmations } in res.unspent_outputs when confirmations > 0
        hash: tx_hash
        index: tx_output_n
        value: value
        script: script
      cb null, unspent
    else cb new Error 'Missing unspent outputs in blockchain.info response'
  xhr.fail (xhr, status, err) ->
    # This isn't actually an error - just send it as an empty array of inputs
    if xhr.status is 500 and xhr.responseText is 'No free outputs to spend'
      cb null, []
    else cb new Error "Cannot load data from blockchain.info: #{ xhr.responseText or err }"

module.exports = { tx_broadcast, load_unspent }
