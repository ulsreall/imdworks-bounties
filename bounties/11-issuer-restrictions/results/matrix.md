| mode | deposit | award/refund while restricted | withdraw | credit preserved | needs issuer action | class |
|---|---|---|---|---|---|---|
| `erc777-style-callback` | accepted, hook re-entry blocked | works | accepted, re-entry blocked | yes | **no** | supported |
| `no-return-values` | accepted | works | succeeds | yes | **no** | supported |
| `standard-exact-6dp` | accepted | n/a | succeeds | yes | **no** | supported |
| `winner-on-recipient-blocklist` | accepted | works | blocked to blocked recipient, redirect allowed | yes | **no** | supported |
| `creator-on-sender-blocklist` | blocked (SENDER_BLOCKED) | works | blocked only if blocked address is the sender | yes | yes | unsupported |
| `fee-on-transfer` | rejected (UnsupportedTransfer) | works | rejected (UnsupportedTransfer), credit preserved | yes | yes | unsupported |
| `paused-transfers` | blocked (TOKEN_PAUSED) | works while paused | blocked, credit preserved | yes | yes | unsupported |
| `returns-false` | blocked | works | blocked, credit preserved | yes | yes | unsupported |
