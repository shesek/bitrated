qs = require 'querystring'
{ Script, Address, Util: { sha256ripe160 } } = Bitcoin
{ SHA256, util: { bytesToBase64, base64ToBytes, bytesToHex, randomBytes }, charenc: { UTF8 } } = Crypto
extend = (dest, source) -> dest[k]=v for own k, v of source when source[k]?; dest

BASE = 'http://localhost:8070/escrow#'
DEFAULT_FEE = 0.0001


# Main controller
render = do ($content = $ '.content') -> (el) -> $content.empty().append el
handle = do (view=require '../views/escrow-content.jade') ->  (query) ->
  return display_error "#{ k } is a required field" for k in [ 'trent', 'terms' ] when not query[k]?
  query[k] = base64ToBytes query[k] for k in [ 'bob', 'alice', 'trent', 'priv', 'terms' ] when query[k]?
  { bob, alice, trent, terms, priv } = query

  # Determine public key from private key
  if priv? then bob = get_pub priv

  # Generate a random private key
  unless bob?
    return document.location.hash = qs.stringify format { alice, trent, terms, priv: randomBytes 32 }

  # TODO trim hash
  terms_hash = SHA256 terms, asBytes: true
  terms_pub = get_pub terms_hash
  terms_text = UTF8.bytesToString terms

  # If we have the other party public key, create the multisig
  if alice?
    multisig_pubkeys = [ bob, alice, (derive_key trent, terms_hash).pub ]
    multisig = create_multisig 2, multisig_pubkeys
    document.title = "Escrow for #{multisig} | Bitscrow"
  else document.title = "Awaiting other party... | Bitscrow"

  render el = $ view {
    # Public keys, private key, and the terms
    bob: (bytesToHex bob), alice: (alice? and bytesToHex alice), trent: (bytesToHex trent)
    priv: (priv? and address_ver priv, 0x80)
    terms: terms_text, terms_hash: (bytesToHex terms_hash)

    # Multisig information
    multisig
    multisig_pubkeys: (multisig? and multisig_pubkeys.map bytesToHex)
    multisig_qr: (multisig? and QRCode.generatePNG multisig)

    # URLs
    alice_url: BASE + qs.stringify format { alice: bob, trent, terms } unless alice?
    bob_url: BASE + qs.stringify format { bob, alice, trent, terms, priv }
    trent_url: BASE + 'dispute&' + qs.stringify format { bob, alice, trent, terms }

    # Settings
    default_fee: DEFAULT_FEE
  }

  el.find('[data-toggle=tooltip]').tooltip()

  if multisig?
    el.find('.add-address').click(add_address).end().
       find('.all').click(send_all).end().
       find('.release-funds').submit(-> tx_dialog tx, priv).end()
    start_update_balance()
    #io.on 'approve-request', ({ addr, tx }) ->
    #  return unless addr is multisig
    #  tx_dialog tx, priv, true
  else
    #io.on 'pubkey', cb = (data) ->
    #  return unless data.terms_hash is terms_hash and data.other is pub
    #  io.off 'pubkey', cb
    #  document.location.hash = qs.stringify { terms, pub, priv, agent, other: data.pub }


# Some helpers
address_ver = (bytes, ver) ->
  addr = new Address bytes
  addr.version = ver
  addr.toString()

format = (d) ->
  d.bob = bytesToBase64 d.bob if d.bob?
  d.alice = bytesToBase64 d.alice if d.alice?
  d.trent = bytesToBase64 d.trent if d.trent?
  d.terms = bytesToBase64 d.terms if d.terms?
  d.priv = address_ver d.priv, 7 if d.priv?
  delete d[k] for k of d when not d[k]?
  d

get_pub = (secexp) ->
  secexp = BigInteger.fromByteArrayUnsigned secexp unless secexp instanceof BigInteger

  (getSECCurveByName 'secp256k1')
    .getG().multiply(secexp)
    .getEncoded()

pad = (bytes, len) -> bytes.unshift 0x00 while bytes.length<len; bytes
create_multisig = (m, pubkeys, version=5) ->
  #pubkeys = (pad pub, 65 for pub in pubkeys)
  script = Script.createMultiSigOutputScript 2, pubkeys
  address_ver (sha256ripe160 script.buffer), version

derive_key = (key, hash, is_private) ->
  if is_private
    secexp = BigInteger.fromByteArrayUnsigned key
    pub = get_pub secexp
  else pub = key

  mpk = pub.slice(1)
  curve = getSECCurveByName 'secp256k1'
  pt = ECPointFp.decodeFrom curve.getCurve(), pub
  N = curve.getN()
  hash_bi = BigInteger.fromByteArrayUnsigned [hash..., mpk...]

  pub: (pt.add curve.getG().multiply hash_bi).getEncoded()
  priv: pad 32, hash_bi.add(secexp).mod(N).toByteArrayUnsigned() if secexp?

add_address = ->
send_all = ->

start_update_balance = ->

release = (tx, priv) ->
  sign tx, priv, false, (signed_tx) ->
    io.emit 'signed', signed_tx

approve = (tx, priv) ->
  sign tx, priv, true, (signed_tx) ->
    broadcast signed_tx

sign = do ->
  dialog = require '../views/tx-dialog.jade'
  
  (tx, priv, is_remote, cb) ->
    return cb null, sign priv, tx if priv?

    el = $ dialog { tx, priv }
    el.find('form').submit (e) ->
      e.preventDefault()

      if signed_tx = (el.find '.signed').val() then # nothing
      else if priv_input = (el.find '.priv').val() then signed_tx = sign priv_input, tx
      else return show_error 'Missing require field, cannot sign transaction.'

      cb null, signed_tx

      if signed_tx.ready then broadcast signed_tx
      else share_partial_tx signed_tx

    el.modal()



run = -> handle qs.parse hash if hash = document.location.hash.substr(1)
$(window).on 'hashchange', run
do run
