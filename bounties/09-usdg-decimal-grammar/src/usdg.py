"""USDG amount grammar and converters.

USDG (the escrow settlement asset on Robinhood Chain) uses 6 decimals, so every
human-readable amount must map to an exact integer of micro-units. Two properties
matter for a bounty board:

  * losslessness  - the string must represent an exact multiple of 1e-6
  * determinism   - one string must have exactly one accepted meaning

This module defines that grammar twice, with two independent implementations:
`parse_amount` (regex driven) and `parse_amount_reference` (a hand written
character scanner that shares no code path with the regex). Both reject anything
that is ambiguous or lossy instead of silently rounding it.

Grammar (canonical form, ASCII only, no signs, no exponent, no separators):

    amount := integer [ "." fraction ]
    integer := "0" | (digit1-9 *digit)
    fraction := 1*6 digit
    value   <= 2**256 - 1 micro-units

Anything else is rejected: leading zeros, "+"/"-", exponents, thousands
separators, locale decimals, whitespace, non-ASCII digits (including fullwidth
and Arabic-Indic), Unicode normalization is deliberately NOT applied.
"""

from __future__ import annotations

import re

DECIMALS = 6
SCALE = 10**DECIMALS
MAX_MICROS = 2**256 - 1  # the escrow stores rewards as uint256 micro-units


class AmountError(ValueError):
    """Raised for any input outside the grammar."""


#: Regex form of the grammar. ASCII-only character classes, matched with
#: ``fullmatch``: a bare ``$`` anchor would also accept a trailing newline
#: ("1\n"), which would make two different strings the same canonical amount.
_CANONICAL_RE = re.compile(r"(0|[1-9][0-9]*)(?:\.([0-9]{1,6}))?", re.ASCII)


def parse_amount(text: str) -> int:
    """Parse a canonical amount into micro-units (regex implementation)."""
    if not isinstance(text, str):
        raise AmountError("amount must be a string")
    if text == "":
        raise AmountError("amount is empty")
    # No Unicode normalisation on purpose: NFKC would fold fullwidth digits into
    # ASCII and silently accept "１" as 1.
    if not text.isascii():
        raise AmountError("amount must be ASCII (no Unicode digits or confusables)")
    m = _CANONICAL_RE.fullmatch(text)
    if m is None:
        raise AmountError(f"amount is not canonical: {text!r}")
    whole, frac = m.group(1), m.group(2) or ""
    micros = int(whole) * SCALE + int(frac.ljust(DECIMALS, "0") or "0")
    if micros > MAX_MICROS:
        raise AmountError("amount exceeds uint256 micro-units")
    return micros


def parse_amount_reference(text: str) -> int:
    """Independent re-implementation used to cross check the regex parser.

    Written as an explicit scanner: no regex, no int() on the fractional part
    beyond a verified digit loop, and its own copy of every rejection rule.
    """
    if not isinstance(text, str) or text == "":
        raise AmountError("amount must be a non-empty string")
    seen_dot = False
    whole_digits: list[str] = []
    frac_digits: list[str] = []
    for ch in text:
        code = ord(ch)
        if 48 <= code <= 57:
            (frac_digits if seen_dot else whole_digits).append(ch)
        elif ch == "." and not seen_dot:
            seen_dot = True
        else:
            raise AmountError(f"illegal character {ch!r} in amount")
    if not whole_digits:
        raise AmountError("amount has no integer part")
    if len(whole_digits) > 1 and whole_digits[0] == "0":
        raise AmountError("leading zeros are not allowed")
    if seen_dot and not frac_digits:
        raise AmountError("trailing separator without fraction")
    if len(frac_digits) > DECIMALS:
        raise AmountError(f"more than {DECIMALS} decimal places: lossy")
    value = 0
    for ch in whole_digits:
        value = value * 10 + (ord(ch) - 48)
    if value > MAX_MICROS // SCALE:
        raise AmountError("amount exceeds uint256 micro-units")
    value *= SCALE
    if frac_digits:
        padded = frac_digits + ["0"] * (DECIMALS - len(frac_digits))
        part = 0
        for ch in padded:
            part = part * 10 + (ord(ch) - 48)
        value += part
    if value > MAX_MICROS:
        raise AmountError("amount exceeds uint256 micro-units")
    return value


def format_amount(micros: int) -> str:
    """Render micro-units back into the canonical string form."""
    if not isinstance(micros, int) or isinstance(micros, bool):
        raise AmountError("micros must be an int")
    if micros < 0:
        raise AmountError("negative amounts are not representable")
    if micros > MAX_MICROS:
        raise AmountError("amount exceeds uint256 micro-units")
    whole, frac = divmod(micros, SCALE)
    if frac == 0:
        return str(whole)
    return _trim(whole, frac)


def _trim(whole: int, frac: int) -> str:
    text = f"{frac:0{DECIMALS}d}".rstrip("0")
    return f"{whole}.{text}"


def parse_amount_float_naive(text: str) -> int:
    """The tempting one-liner. Included only to demonstrate its failure modes."""
    return int(float(text) * SCALE)


def parse_amount_round_naive(text: str) -> int:
    """Float parse with rounding instead of truncation: still lossy."""
    return round(float(text) * SCALE)
