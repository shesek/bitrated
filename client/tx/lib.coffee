{ Bitcoin, Crypto, BigInteger } = require '../../lib/bitcoinjs-lib.js'
{ Script, ECKey } = Bitcoin
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


module.exports = { sign_tx, calc_total_in, sum_inputs, is_final_tx }
