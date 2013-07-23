{ Bitcoin, Crypto, BigInteger } = require '../../lib/bitcoinjs-lib.js'
{ iferr, error_displayer } = require '../util.coffee'
{ get_address, parse_address, parse_key_bytes, decode_raw_tx, get_pub, ADDR_PUB, ADDR_PRIV } = require '../bitcoin.coffee'
{ sign_tx, calc_total_in, sum_inputs } = require './lib.coffee'
{ tx_listen, load_unspent } = require './networking.coffee'
{ bytesToHex } = Crypto.util
{ Transaction, Util: BitUtil } = Bitcoin

# Initialize the transaction builder interface,
# and return a teardown function
tx_builder = do (addr_tmpl=null) -> (el, { key, trent, multisig, script, channel, fees }, cb) ->
  { pub, priv } = parse_key_bytes key
  fees = BitUtil.parseValue fees unless fees instanceof BigInteger
  display_error = error_displayer el
  unspent = balance = null
  addresses = el.find('.addresses')

  # Add address
  el.find('.add-address').click ->
    addr_tmpl ||= addresses.find('.address:eq(0)').clone()
      .find('input').val('').end()
      .find('.add-address').toggleClass('add-address del-address').end()
      .find('.icon-plus').toggleClass('icon-plus icon-minus').end()
    addresses.append addr_tmpl.clone()

  # Delete address
  el.on 'click', '.del-address', -> $(this).closest('.address').remove()

  # Address dropdown items
  el.on 'click', '[data-address]', ->
    $(this).closest('.address').find('input[name=address]').val $(this).data('address')

  # Pay remaining, minus fees
  el.on 'click', '.pay-remaining', ->
    val_el = $(this).closest('.address').find('[name=value]')
    spent = el.find('.address input[name=value]').not(val_el)
      .filter(->!!@value)
      .map(-> BitUtil.parseValue @value).get()
    remain = balance.subtract(sum_inputs spent).subtract(fees)
    remain = BigInteger.ZERO if (remain.compareTo BigInteger.ZERO) < 0
    val_el.val BitUtil.formatValue remain

  # Update balance
  el.find('.update-balance').click update_balance = ->
    load_unspent multisig, iferr display_error, (_unspent) ->
      unspent = _unspent
      balance = sum_inputs unspent
      $('.balance').text (BitUtil.formatValue balance)+' BTC'
  do update_balance

  cb_success = cb.bind null, null

  # Release button - open dialog for confirmation
  el.find('.release').click ->
    tx_dialog {
      pub, priv, script
      tx: build_tx unspent, el
      initiator: 'self'
    }, iferr display_error, cb_success
    
  # Subscribe to transaction requests
  tx_unlisten = tx_listen channel, (tx) ->
    # TODO ignore requests made by the viewing user
    # TODO validate tx
    # TODO validate signature
    try
      tx.total_in = calc_total_in tx, unspent
      tx_dialog {
        pub, priv, tx, script
        initiator: 'other'
      }, iferr display_error, cb_success


# Build transaction with the given inputs and form outputs
build_tx = (inputs, $form) ->
  tx = new Transaction

  # Add inputs
  tx.addInput { hash }, index for { hash, index } in inputs
  tx.total_in = sum_inputs inputs
  
  # Read outputs from DOM
  $form.find('.address').each ->
    $this = $ this
    try tx.addOutput
      hash: parse_address $this.find('[name=address]').val(), ADDR_PUB
      BitUtil.parseValue $this.find('[name=value]').val()
    # just ignore invalid addresses/amount, the user still have to
    # confirm the transaction after that and should see it missing
  tx

# Display the transaction dialog
tx_dialog = do (view=require './views/tx-dialog.jade') ->
  ({ pub, priv, tx, script, initiator }, cb) ->
    total_out = sum_inputs (BitUtil.valueToBigInt value.slice().reverse() for { value } in tx.outs)
    if tx.total_in? and (total_out.compareTo tx.total_in) > 0
      return cb new Error 'Insufficient funds. If the payment was sent recently,
                           it might not be confirmed yet.
                           You can refresh the balance to check for new payments.'
    dialog = $ view {
      outs: for { script: out_script, value } in tx.outs
        address: get_address out_script.simpleOutHash(), ADDR_PUB
        value: BitUtil.formatValue value.slice().reverse()
      has_priv: priv?
      pub_address: get_address pub, ADDR_PUB
      total_in: BitUtil.formatValue tx.total_in
      fees: BitUtil.formatValue tx.total_in.subtract(total_out)
      rawtx: bytesToHex tx.serialize()
      initiator
      final: initiator is 'other'
    }

    display_error = error_displayer dialog.find('.modal-body .errors')

    get_signed_tx = ->
      # Sign with the known private key
      if priv?
        sign_tx priv, tx, script
      # Use user-provided private key
      else if priv_text = dialog.find(':visible[name=priv]').val()
        priv_ = parse_address priv_text, ADDR_PRIV
        throw new Error 'Invalid private key provided' unless (bytesToHex get_pub priv_) is (bytesToHex pub)
        sign_tx priv_, tx, script
      # Use user-provided signed transaction
      else if rawtx = dialog.find(':visible[name=signed-raw-tx]')
        signed_tx = decode_raw_tx rawtx
        throw new Error 'Invalid signature provided' unless verify_tx_sig pub, signed
        signed_tx
      else
        throw new Error 'Please provide the private key or the signed transaction'

    dialog.find('.authorize .ok').click sure_cb = ->
      dialog
        .find('.authorize').hide().end()
        .find('.confirm').show()

    dialog.find('.confirm .ok').click authorize = ->
      try
        cb null, get_signed_tx()
        dialog.modal 'hide'
      catch e then display_error e

    dialog.on 'hidden', -> do dialog.remove
    dialog.modal()

module.exports = tx_builder
