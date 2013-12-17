{ Util: { parseValue, bytesToNum }, convert: { bytesToHex, hexToBytes } } = require 'bitcoinjs-lib'

# Send transaction to Bitcoin network using blockchain.info's pushtx
tx_broadcast = (tx, cb) ->
  rawtx = bytesToHex tx.serialize()

  # Temporarily switch to coinb.in, bc.i's pushtx is buggy
  #$.post('https://blockchain.info/pushtx?cors=true', tx: rawtx)
  #  .fail((xhr, status, err) -> cb new Error "Error from blockchain.info pushtx: #{ xhr.responseText or err }")
  #  .done((data) -> cb null, data)

  xhr = $.post 'https://coinb.in/api/', {
    uid: 1
    key: '12345678901234567890123456789012'
    setmodule: 'bitcoin'
    request: 'sendrawtransaction'
    rawtx
  }, 'xml'
  xhr.fail (xhr, status, err) ->
    cb new Error "Error from coinbin pushtx: #{ xhr.responseText or err }"
  xhr.done (data) ->
    if data.querySelector('result')?.textContent is '1'
      cb null
    else
      err = decodeURIComponent data.querySelector('response')?.textContent.replace /\+/g, ' '
      cb new Error "Error from coinbin pushtx: #{err ? 'unknown error'}"

# Load unspent inputs (from blockchain.info)
load_unspent = (address, cb) ->
  xhr = $.get "https://blockchain.info/unspent?active=#{address}&cors=true"
  xhr.done (res) ->
    if res.unspent_outputs
      unspent = for { tx_hash, tx_output_n, value, script, confirmations } in res.unspent_outputs when confirmations > 0
        hash: bytesToHex (hexToBytes tx_hash).reverse()
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
