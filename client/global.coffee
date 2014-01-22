# Display email fraud warning to first time visitors
#
# Browsers with no localStorage will fallback to always displaying it
unless localStorage?.displayed_email_warning
  localStorage?.displayed_email_warning = true

  # Load those on demand, only when needed
  document.write '''
    <link rel="stylesheet" href="lib/pnotify/jquery.pnotify.default.css">
    <script src="lib/pnotify/jquery.pnotify.min.js"></script>
  '''

  $ -> $.pnotify
    title: 'Got an email from us?'
    text: '
      Bitrated never sends emails with payment addresses.
      If you got one, this is probably a fraud attempt.
      <a href="help/email-fraud.html">Click here</a> to learn more.
    '
    sticker: false

