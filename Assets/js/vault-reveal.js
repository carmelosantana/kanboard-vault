/*
 * The one-time share page's script (spec: One-time shares → Opening a share). Task 18 implements it: read the id from
 * the query string and k ‖ b from the #fragment, POST {id, b, csrf_token} to #vault-reveal's data-reveal-url when the
 * Reveal button is pressed (never on load), then decrypt in the page with the AD enc("share", 1, id, expires_at,
 * has_passphrase) from the answer. Until then the page reveals nothing.
 */
(function () {
  'use strict';
})();
