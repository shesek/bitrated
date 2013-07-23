module.exports = (parent) ->
  io = socketio.listen server, log: !!process.env.SOCKETIO_LOG
  io.set 'transports', ['xhr-polling'] if process.env.NO_WEBSOCKET

  io.on 'connection', (socket) ->
    # allow clients to join and leave rooms
    socket.on 'join', (room) -> socket.join room
    socket.on 'part', (room) -> socket.leave room

    # forward handshake replies (base64 public key, base64 signature and
    # base58-check multisig for verification)
    socket.on 'hs', (room, data) ->
      (io.sockets.in room).emit 'hs:' + room, data

    # forward transactions (base64 raw transaction)
    socket.on 'tx', (room, tx) ->
      (io.sockets.in room).emit 'tx:' + room, tx
  io

  app = express().configure ->
    @post '/message/:channel'

  { app, io }
