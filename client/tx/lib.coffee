{ Bitcoin, Crypto, BigInteger } = require '../../lib/bitcoinjs-lib.js'
{ Script, ECKey } = Bitcoin
{ get_address, ADDR_PRIV } = require '../../lib/bitcoin.coffee'
{ util: { bytesToHex, bytesToBase64 }, charenc: { UTF8 } } = Crypto
{ OP_0 } = Bitcoin.Opcode.map
SIGHASH_ALL = 0x01

# Sign a multisig transaction
# https://en.bitcoin.it/wiki/BIP_0011#Specification (m-of-n)
# https://en.bitcoin.it/wiki/BIP_0016#Specification (p2sh)
sign_tx = do ->
  ## Some helpers:
  
  # Get previous signature
  get_prev_sig = (script) ->
    unless script.chunks.length is 3 and script.chunks[0] is OP_0 and Array.isArray script.chunks[1]
      throw new Error 'Invalid script signature'
    script.chunks[1]

  # Sign a single input, optionally already partially-signed with another key
  sign_input = (key, multisig_script, tx, i, inv, hash_type) ->
    hash = tx.hashTransactionForSignature multisig_script, i, hash_type
    signature = key.sign hash
    in_script = new Script
    in_script.writeOp OP_0
    in_script.writeBytes get_prev_sig inv.script if inv.script.buffer.length
    in_script.writeBytes [ signature..., hash_type ]
    in_script.writeBytes multisig_script.buffer
    in_script

  # Main function - sign a transaction
  (priv, tx, multisig_script, hash_type=SIGHASH_ALL) ->
    tx = tx.clone()
    key = new ECKey priv
    for inv, i in tx.ins
      inv.script = sign_input key, multisig_script, tx, i, inv, hash_type
    tx

calc_total_in = (tx, inputs) ->
  input_map = {}
  input_map["#{hash}:#{index}"] = value for { hash, index, value } in inputs
  sum_inputs tx.ins.map ({ outpoint: { hash, index } }) ->
    throw new Error 'Invalid input' unless value = input_map["#{hash}:#{index}"]
    value


sum_inputs = (inputs) -> inputs.reduce ((a, b) -> a.add (b.value ? b)), BigInteger.ZERO

is_final_tx = ({ ins }) ->
  # The final tx script of an 2-of-3 should have 4 chunks:
  # OP_0, 1st signature, 2nd signature, redeemScript
  return false for inv in ins when inv.script.chunks.length isnt 4 or inv.script.chunks[0] isnt OP_0
  true

# Decode raw transaction into a Transaction instance
decode_raw_tx = do ->
  { Transaction, TransactionIn, TransactionOut } = Bitcoin

  # Parse an little-endian bytearray of length `size` as an integer
  # Works for numbers up to 32-bit only
  parse_int = (size) -> (bytes) ->
    n = 0
    n += (bytes.shift() & 0xff) << (8 * i) for i in [0...size]
    n
  u8  = (bytes) -> bytes.shift()
  u16 = parse_int 2
  u32 = parse_int 4
  # 64 bit numbers are kept as bytes
  # (bitcoinjs-lib expects them that way)
  u64 = (bytes) -> bytes.splice 0, 8

  # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
  varint = (bytes) ->
    switch n = u8 bytes
      when 0xfd then u16 bytes
      when 0xfe then u32 bytes
      when 0xff then u64 bytes
      else n

  # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_string
  varchar = (bytes) -> bytes.splice 0, varint bytes

  (bytes) ->
    bytes = bytes.slice() # clone
    ver = u32 bytes
    throw new Error 'Unsupported version' unless ver is 0x01

    tx = new Transaction

    # Parse inputs
    in_count = varint bytes
    for [0...in_count]
      tx.addInput new TransactionIn
        outpoint:
          hash: bytesToBase64 bytes.splice 0, 32
          index: u32 bytes
        script: varchar bytes
        seq: u32 bytes

    # Parse outputs
    out_count = varint bytes
    for [0...out_count]
      tx.addOutput new TransactionOut
        value: u64 bytes
        script: varchar bytes

    tx.lock_time = u32 bytes

    tx

# Transform tx data to human readable format
format_locals = (data) ->
  data[k] = bytesToHex data[k] for k in ['bob', 'alice', 'trent'] when data[k]?
  data.bob_priv = get_address data.bob_priv, ADDR_PRIV if data.bob_priv?
  data.terms = UTF8.bytesToString data.terms if data.terms?
  data.proof = bytesToBase64 data.proof if data.proof?
  data

module.exports = {
  sign_tx, decode_raw_tx, is_final_tx
  calc_total_in, sum_inputs
  format_locals
}
