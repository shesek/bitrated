socketio = require 'socket.io'

module.exports = (server) ->
  { Message } = @models

  io = socketio.listen server, log: !!process.env.SOCKETIO_LOG
  io.set 'transports', ['xhr-polling'] if process.env.NO_WEBSOCKET

  io.on 'connection', (socket) ->
    # Join rooms
    socket.on 'join', (room, cb) ->
      socket.join room

    # Leave rooms
    socket.on 'part', (room) -> socket.leave room

    # Forward handshake replies
    socket.on 'handshake', (room, msg) -> socket.broadcast.to(room).emit(room, msg)
    
    # Forward and store messages
    socket.on 'msg', (room, tx) ->
      socket.broadcast.to(room).emit(room, tx)
      #msg = new Message { room, tx }
      #msg.save (err) ->
      #  socket.emit 'error', iferr if err?
  io

# load stored messages
#Message.find { room }, iferr cb, (msgs) ->
#  socket.emit room, msg for msg in msgs
#  cb null


# TODO
# - Encrypt messages end-to-end (using Bitcoin key pair?)
# - Validate identity of senders with the signature
#   (currently relies on the room name being unique and
#    hard to guess, unless you have access to the URL)

