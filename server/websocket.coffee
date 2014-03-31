socketio = require 'socket.io'
{ randomBytes } = require 'crypto'

ACK_TIMEOUT = 20*60*1000 # 20 seconds

module.exports = (server) ->
  { Message } = @models

  io = socketio.listen server, log: !!process.env.SOCKETIO_LOG
  io.set 'transports', ['xhr-polling'] if process.env.NO_WEBSOCKET

  io.on 'connection', (socket) ->
    # Join rooms
    socket.on 'join', (room) ->
      socket.join room
      Message.find { room }, (err, msgs) ->
        return socket.emit 'error', err if err?
        socket.emit room, data for { data } in msgs
        return

    # Leave rooms
    socket.on 'part', (room) -> socket.leave room

    # Forward handshake replies and the script verification messages
    socket.on 'handshake', (room, msg, cb) ->
      ack_id = ack_listen io.sockets.clients(room), cb
      socket.broadcast.to(room).emit room, msg, ack_id
    
    # Forward and store messages
    socket.on 'msg', (room, data) ->
      socket.broadcast.to(room).emit room, data
      msg = new Message { room, data }
      msg.save (err) ->
        socket.emit 'error', err if err?
  io

# create a unique event name, start listening for ack responses
# over that event and return the event name
#
# this can usually be done with socket.io built-in ack mechanism by
# passing a callback, but that doesn't work when broadcasting to a room
# (https://github.com/LearnBoost/socket.io/issues/464)
ack_listen = (sockets, cb) ->
  ack_id = randomBytes(25).toString('base64')
  listeners = for socket in sockets then do (socket) ->
    socket.once ack_id, ack_cb = (a..., msg_cb) ->
      msg_cb() # signal the client that the message was recivied
      unlisten() # stop listening for more messages on this ack_id
      cb a... # pass the result to the callback
    [ socket, ack_cb ]

  # stop listening on all sockets
  unlisten = ->
    socket.removeListener ack_id, ack_cb for [ socket, ack_cb ] in listeners
    clearTimeout ack_timer

  # automatically stop listening
  ack_timer = setTimeout unlisten, ACK_TIMEOUT

  ack_id


# load stored messages
#Message.find { room }, iferr cb, (msgs) ->
#  socket.emit room, msg for msg in msgs
#  cb null



