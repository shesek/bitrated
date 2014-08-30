{ convert: { bytesToHex } } = require 'bitcoinjs-lib'

CHAIN_KEY = '952d0be9540d035cb60f57bbc9b2a00c'

# Send transaction to Bitcoin network via HelloBlock
tx_broadcast = (tx, cb) ->
  rawtx = bytesToHex tx.serialize()
  xhr = $.ajax 'https://mainnet.helloblock.io/v1/transactions', {
    method: 'post'
    data: rawTxHex: rawtx
  }, 'xml'
  xhr.fail (xhr, status, err) ->
    cb new Error "Error while broadcasting transaction."
  xhr.done (res) ->
    if res.status is 'success' then cb null
    else cb new Error res.message

# Load unspent inputs via Chain.com
load_unspent = (address, cb) ->
  xhr = $.get "https://api.chain.com/v1/bitcoin/addresses/#{ address }/unspents?api-key-id=#{ CHAIN_KEY }"
  xhr.done (res) ->
    if Array.isArray res
      unspent = for { transaction_hash, output_index, value, script_hex, confirmations } in res when confirmations > 0
        hash: transaction_hash
        index: output_index
        value: value
        script: script_hex
      cb null, unspent
    else cb new Error 'Cannot load unspent outputs'
  xhr.fail (xhr, status, err) ->
    cb new Error "Cannot load unspent outputs"

module.exports = { tx_broadcast, load_unspent }
