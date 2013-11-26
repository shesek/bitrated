{ BigInteger, Transaction, TransactionOut, Util, convert: { bytesToHex, hexToBytes } } = require 'bitcoinjs-lib'
{ iferr, error_displayer, rpad } = require '../../lib/util.coffee'
{ get_address, parse_address, parse_key_bytes, get_pub
  create_out_script, get_script_address
  ADDR_PUB, ADDR_PRIV, ADDR_P2SH } = require '../../../lib/bitcoin/index.coffee'
{ sign_tx, calc_total_in, sum_inputs, decode_raw_tx, verify_tx_sig } = require '../../../lib/bitcoin/tx.coffee'
{ tx_listen, load_unspent } = require './networking.coffee'

# Initialize the transaction builder interface
tx_builder = (el, { key, trent, multisig, script, channel, fees }, cb) ->
  { pub, priv } = parse_key_bytes key
  display_error = error_displayer el
  unspent = balance = null
  addresses = el.find('.addresses')

  # Add address
  el.find('.add-address').click do (addr_tmpl=null) -> ->
    addr_tmpl ?= addresses.find('.address:eq(0)').clone()
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
      .map(-> +Util.parseValue @value).get()
    remain = Math.max 0, balance - (sum_inputs spent) - fees
    val_el.val Util.formatValue remain

  # Pay %
  el.on 'click', '.pay-some', ->
    val_el = $(this).closest('.address').find('[name=value]')
    return unless percentage = prompt 'Enter the percentage to pay (between 0% and 100%)'
    percentage = +percentage.replace /\s|%/g, ''
    return display_error 'Invalid percentage amount' if isNaN percentage
    amount = balance/100*percentage
    val_el.val Util.formatValue amount

  # Update balance
  el.find('.update-balance').click update_balance = ->
    refresh_icon = $(this).find('i').addClass 'icon-spin'
    load_unspent multisig, (err, _unspent) ->
      refresh_icon.removeClass 'icon-spin'
      return display_error err if err?
      unspent = _unspent
      balance = sum_inputs unspent
      $('.balance').text (Util.formatValue balance)+' BTC'
  do update_balance
  
  cb_success = cb.bind null, null

  # Helper for displaying the transaction dialog with
  # all the common data
  show_dialog = (tx, initiator) ->
    try
      tx.total_in ?= calc_total_in tx, unspent
      tx_dialog { pub, priv, script, tx, el, initiator },
                iferr display_error, cb_success
    catch err then display_error err

  # Release button - open dialog for confirmation
  el.find('.release').click ->
    show_dialog (build_tx unspent, el), 'self'

  # Input raw transaction
  el.find('.input-rawtx').click ->
    input_rawtx_dialog iferr display_error, (tx) ->
      show_dialog tx, 'self'

  # Get raw transaction
  el.find('.show-rawtx').click ->
    try show_rawtx_dialog build_tx unspent, el
    catch e then display_error e

  # Add transaction request to list
  add_tx_request = do ($requests = $ '.tx-requests') -> (tx) ->
    # TODO validate tx
    # TODO validate signature
    txid = bytesToHex tx.getHash()
    $(document.createElement 'li')
      .text("#{ txid }")
      .click(show_dialog.bind null, tx, 'other')
      .appendTo($requests.find 'ul')
    $requests.addClass 'has-requests'

  # Subscribe to transaction requests
  tx_unlisten = tx_listen channel, add_tx_request

# Build transaction with the given inputs and parse outputs from <form>
build_tx = (inputs, $form) ->
  tx = new Transaction

  # Add inputs
  tx.addInput { hash }, index for { hash, index } in inputs
  tx.total_in = sum_inputs inputs
  
  # Read outputs from DOM
  $form.find('.address').each ->
    $this = $ this
    amount_bi = Util.parseValue $this.find('[name=value]').val()
    tx.addOutput new TransactionOut
      script: create_out_script $this.find('[name=address]').val()
      value: rpad amount_bi.toByteArrayUnsigned().reverse(), 8
  tx

# Display the transaction dialog
tx_dialog = do (view=require '../views/dialogs/confirm-tx.jade') ->
  ({ pub, priv, tx, script, initiator }, cb) ->
    total_out = sum_inputs (value for { value } in tx.outs)
    if tx.total_in? and (total_out > tx.total_in)
      return cb new Error 'Insufficient funds. If the payment was sent recently,
                           it might not be confirmed yet.
                           You can refresh the balance to check for new payments.'
    unless tx.outs.length
      return cb new Error 'No outputs provided'

    dialog = $ view {
      outs: for { script: out_script, value } in tx.outs
        address: get_script_address out_script
        value: Util.formatValue value
      has_priv: priv?
      pub_address: get_address pub, ADDR_PUB
      total_in: Util.formatValue tx.total_in
      fees: Util.formatValue tx.total_in - total_out
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
      else if rawtx = dialog.find(':visible[name=signed-raw-tx]').val()
        try
          rawtx = JSON.parse(rawtx).hex if ~rawtx.indexOf '{'
          rawtx = hexToBytes rawtx
          signed_tx = decode_raw_tx rawtx
        catch e then throw new Error 'Invalid raw transaction format'
        throw new Error 'Invalid signature provided' unless verify_tx_sig pub, signed_tx, script
        signed_tx
      else
        throw new Error 'Please provide the private key or the signed transaction'

    dialog.find('.authorize .ok').click ->
      dialog
        .find('.authorize').hide().end()
        .find('.confirm').show().end()

    dialog.find('.confirm .ok').click ->
      try
        cb null, get_signed_tx()
        dialog.modal 'hide'
      catch err then display_error err

    dialog.on 'hidden', -> do dialog.remove
    dialog.modal()

show_rawtx_dialog = do (view = require '../views/dialogs/show-rawtx.jade') -> (tx) ->
  rawtx = bytesToHex tx.serialize()
  dialog = $ view { rawtx }
  dialog.on 'hidden', -> do dialog.remove
  dialog.modal()

input_rawtx_dialog = do (view = require '../views/dialogs/input-rawtx.jade') -> (cb) ->
  dialog = $ view()
  display_error = error_displayer dialog.find('.errors')

  dialog.find('form').on 'submit', (e) ->
    e.preventDefault()
    try
      cb null, decode_raw_tx hexToBytes dialog.find('[name=rawtx]').val()
      dialog.modal 'hide'
    catch e then display_error e

  dialog.on 'hidden', -> do dialog.remove
  dialog.modal()

module.exports = tx_builder
