{ random_privkey } = require './bitcoin.coffee'

form = $ 'form.arbitrate'

# Set random private key
form.find('input[name=trent]').val random_privkey()

form.find('input[name=register]').change -> form.find('.register-fields').toggle('slow')

form.submit (e) ->
  e.preventDefault()


