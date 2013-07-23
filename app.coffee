{ createServer } = require 'http'
{ NODE_ENV, PORT } = process.env
PORT or= 8070

# On production, nginx is used to serve static files
# In development, web.coffee compiles files on-the-fly and serves them
server = if NODE_ENV is 'production' then createServer() \
         else createServer require './web.coffee'

require('./websocket')(server)

server.listen PORT, -> console.log "Listening on #{PORT}"

