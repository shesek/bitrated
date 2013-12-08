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
      if err is 'unexpected error, try again in a moment'
        # Coinbin seems to return that error for multisig transactions,
        # even though they are sent correctly to the network.
        # As a temporary and extremly hacky solution, until bc.i is working
        # again or until I'll setup a pushtx service on bitrated's servers
        # (which I really prefer to avoid), treat that error as a success.
        # Yes, this is an extremely horrific solution, but its better than
        # bitrated not working at all and its just temporary.
        cb null
      else cb "Error from coinbin pushtx: #{err ? 'Unknown error from coinbin pushtx'}"

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
