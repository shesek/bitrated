express = require 'express'
marked = require 'marked'
ValidationError = require 'mongoose/lib/errors/validation'
{ PUBKEY_LEN } = require './client/bitcoin.coffee'
HASH_LEN = 32
#{ Bitcoin, Crypto } = require '../lib/bitcoinjs-lib.js'


{ iferr, only } = require './util'
{ join } = require 'path'

USERS_PER_PAGE = 35

module.exports = ({ models }) -> express().configure ->
  @set 'views', join __dirname, 'views', 'user'
  @set 'view engine', 'jade'
  @locals.marked = marked

  { User, Rating } = models

  @param 'user', (req, res, next, id) ->
    # Allows usernames, base64 pubkeys and base64 pubkeys triple sha256 hashes
    search =
      if id.length <= 15 then _id: id
      else switch (bytes = new Buffer id, 'base64').length
        when PUBKEY_LEN then pubkey: bytes
        when HASH_LEN then pubkey_hash: bytes
        else throw new Error 'Invalid key length'

    User.findOne search, iferr next, (user) ->
      return res.send 404 unless user?
      req.user = user
      next null

  # Signup (JSON only)
  @post '/', (req, res, next) ->
    { username, pubkey, content, sig } = req.body
    user = new User { _id: username, pubkey, content, sig }
    user.save (err) ->
      if err?
        if err instanceof ValidationError
          res.send 400, err
        else if ~err.message.indexOf 'E11000 duplicate key error index'
          res.send 422, message: 'Username is already taken'
        else next err
      else res.redirect 303, user._id

  # Profile
  @get '/:user', (req, res, next) ->
    user = format_user req.user
    res.format
      json: -> res.json user
      html: -> res.render 'profile', { user }
      text: -> res.send """Username: #{user.username}
                           Pubkey: #{user.pubkey}
                           Signature: #{user.sig}
                           \n---------------------\n
                           #{user.content}"""

  # Update profile
  @patch '/:user', (req, res, next) ->
    req.user.set content: req.body.content, sig: body.sig
    user.save iferr next, -> res.redirect user._id

  # User list
  user_list = (req, res, next) ->
    page = req.params.page or 1
    User.find().paginate page, USERS_PER_PAGE, iferr next, (users, total) ->
      is_html = req.accepts('html, json, text') is 'html'
      users = users.map format_user
      pages = Math.ceil total / USERS_PER_PAGE
      res.format
        json: ->
          res.set 'X-Pagination-Page': page, 'X-Pagination-Pages': pages
          res.json users
        html: -> res.render 'index', { users, page, pages }
  @get '/', user_list
  @get '/page/:page', user_list

  format_user = ({ _id, pubkey, content, sig }) =>
    username: _id
    pubkey: pubkey.toString 'hex'
    content: content
    sig: pubkey.toString 'base64'
    profile_url: @settings.url + "u/#{_id}"
    tx_url: @settings.url + "tx.html#trent=#{encodeURIComponent pubkey.toString 'base64'}"

  ###
  # Rate
  @get '/u/:user/rate', identify, (req, res) -> res.render 'rate', user: req.user
  @post '/u/:user/rate', identify, (req, res, next) ->
    rating = new Rating
      _user: req.user._id, _rater: req.auth._id
      rating: req.body.rating, content: req.body.content
    rating.save iferr next, -> req.redirect 303, "#{req.user._id}/rating/#{rating._id}"

  # Rating
  @get '/:user/rating/:rating_id', (req, res, next) ->
    Rating.find(req.params.rating_id).populate('_user _rater').exec iferr next, (rating) ->
      return res.send 404 unless rating? and rating.user is req.user._id
      res.format
        json: -> res.json rating
        html: -> res.render 'rating', { rating }
  ###
