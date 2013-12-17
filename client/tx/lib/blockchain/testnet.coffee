{ convert: { bytesToHex } } = require 'bitcoinjs-lib'

TESTNET_API = $('meta[name=testnet-api]').attr('content')

# Send transaction to Bitcoin testnet network
tx_broadcast = (tx, cb) ->
  tx = bytesToHex tx.serialize()
  $.post(TESTNET_API + 'pushtx', { tx })
    .fail((xhr, status, err) -> new Error cb "Cannot pushtx: #{ xhr.responseText or err }")
    .done((data) -> cb null, data)

# Load unspent inputs
load_unspent = (address, cb) ->
  xhr = $.get TESTNET_API + "unspent/#{address}"
  xhr.done (res) ->
      unspent = for { txid, n, value, script } in res
        { hash: txid, index: n, value, script }
      cb null, unspent
  xhr.fail (xhr, status, err) -> cb new Error "Cannot load unspent inputs: #{ xhr.responseText or err}"

module.exports = { tx_broadcast, load_unspent }
