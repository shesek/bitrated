socketio = require 'socket.io'
RedisStore = require 'socket.io/lib/stores/redis'

module.exports = (server) ->
  io = socketio.listen server, log: !!process.env.SOCKETIO_LOG
  io.set 'transports', ['xhr-polling'] if process.env.NO_WEBSOCKET

  io.on 'connection', (socket) ->
    # allow clients to join and leave rooms
    socket.on 'join', (room) -> socket.join room
    socket.on 'part', (room) -> socket.leave room

    # Forward messages between users
    socket.on 'msg', (room, msg) -> socket.broadcast.to(room).emit(room, msg)
  io

# TODO
# - Encrypt messages end-to-end (using Bitcoin key pair?)
# - Validate identity of senders with the signature
#   (currently relies on the room name being unique and
#    hard to guess, unless you have access to the URL)

