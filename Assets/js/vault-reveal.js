/*
 * The one-time share page's script (spec: One-time shares → Opening a share). Task 18 implements it: read the id from
 * the query string and k ‖ b from the #fragment, POST {id, b, csrf_token} to #vault-reveal's data-reveal-url when the
 * Reveal button is pressed (never on load), then decrypt in the page with the AD enc("share", 1, id, expires_at,
 * has_passphrase) from the answer. Until then the page reveals nothing. The page has no <form> and no named field
 * (fix I1): bind [data-vault-reveal-button] and Enter in [data-vault-reveal-passphrase] here, never a native submit.
 */
(function () {
  'use strict';
})();
