{ Script, Key, BigInteger, Opcode, Transaction, TransactionIn, TransactionOut, Crypto, convert, ecdsa } = require 'bitcoinjs-lib'
{ bytesToHex } = convert
{ parseSig, recoverPubKey } = ecdsa
{ UTF8 } = Crypto.charenc
{ OP_0 } = Opcode.map
SIGHASH_ALL = 0x01

# Sign 2-of-3 transaction with the given private key
#
# https://en.bitcoin.it/wiki/BIP_0011#Specification (m-of-n)
# https://en.bitcoin.it/wiki/BIP_0016#Specification (p2sh)
sign_tx = do ->
  # Get previous signature
  get_prev_sig = (script) ->
    unless script.chunks.length is 3 and script.chunks[0] is OP_0 and Array.isArray script.chunks[1]
      throw new Error 'Invalid script signature'
    script.chunks[1]


  # Recover the pubkey used to sign a multisig input
  #
  # Uses brote force on all possible public keys and recovery parameters until
  # something matches.
  recover_sig_pubkey = (sig, hash, multisig_pubs) ->
    { r, s } = parseSig sig
    for pubkey in multisig_pubs then for i in [0..3]
      pubkey = (recoverPubKey r, s, hash, i).getPub()
      return pubkey if (bytesToHex pubkey) in multisig_pubs


  # Export main function
  (priv, tx, multisig_script, hash_type=SIGHASH_ALL) ->
    tx = tx.clone()
    key = new Key priv
    multisig_pubs = multisig_script.chunks[1...-2].map(bytesToHex)
    unless ~pub_index = multisig_pubs.indexOf(bytesToHex key.getPub())
      throw new Error 'Supplied key not found in multisig pubkeys'

    # Sign a single input, optionally already partially-signed with another key
    sign_input = (key, multisig_script, tx, i, inv, hash_type) ->
      hash = tx.hashTransactionForSignature multisig_script, i, hash_type

      # Detect previous signature and its index in the pubkeys list
      if inv.script.buffer.length
        prev_sig = get_prev_sig inv.script
        # [...-1] is used to strip out the hash type
        prev_pub = recover_sig_pubkey prev_sig[...-1], hash, multisig_pubs
        unless ~prev_pub_index = multisig_pubs.indexOf(bytesToHex prev_pub)
          throw new Error 'Signature pubkey not found in multisig pubkeys'

      signature = key.sign hash
      in_script = new Script
      in_script.writeOp OP_0
      in_script.writeBytes prev_sig if prev_sig? and prev_pub_index < pub_index
      in_script.writeBytes [ signature..., hash_type ]
      in_script.writeBytes prev_sig if prev_sig? and prev_pub_index > pub_index
      in_script.writeBytes multisig_script.buffer
      in_script

    for inv, i in tx.ins
      inv.script = sign_input key, multisig_script, tx, i, inv, hash_type
    tx

# Calc the total amount paid in `tx`, using the unspent inputs `inputs`
calc_total_in = (tx, inputs) ->
  input_map = {}
  input_map["#{hash}:#{index}"] = value for { hash, index, value } in inputs
  sum_inputs tx.ins.map ({ outpoint: { hash, index } }) ->
    throw new Error 'Invalid input' unless value = input_map["#{hash}:#{index}"]
    value

# Calc the sum of the given `inputs`
#
# Uses the `value` property if it exists, otherwise uses the value itself
sum_inputs = (inputs) -> inputs.reduce ((a, b) -> a + (b.value ? b)), 0

# Checks if a transaction is signed by both parties
is_final_tx = ({ ins }) ->
  # The final tx script of an 2-of-3 should have 4 chunks:
  # OP_0, 1st signature, 2nd signature, redeemScript
  return false for inv in ins when inv.script.chunks.length isnt 4 or inv.script.chunks[0] isnt OP_0
  # @TODO: validate sigs
  true

# Decode raw transaction into a Transaction instance
decode_raw_tx = do ->
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
          hash: bytesToHex (bytes.splice 0, 32).reverse()
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

module.exports = {
  sign_tx, decode_raw_tx, is_final_tx
  calc_total_in, sum_inputs
}
