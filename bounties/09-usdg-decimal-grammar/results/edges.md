| input | verdict | detail |
|---|---|---|
| `0` | accept | 0 micros -> 0 |
| `0.0` | accept | 0 micros -> 0 |
| `1` | accept | 1000000 micros -> 1 |
| `1.000000` | accept | 1000000 micros -> 1 |
| `0.000001` | accept | 1 micros -> 0.000001 |
| `999999999999999999999999999999` | accept | 999999999999999999999999999999000000 micros -> 999999999999999999999999999999 |
| `115792089237316195423570985008687907853269984665640564039457584007913129.639935` | accept | 115792089237316195423570985008687907853269984665640564039457584007913129639935 micros -> 115792089237316195423570985008687907853269984665640564039457584007913129.639935 |
| `0.0000001` | reject | 7 decimal places (lossy) |
| `1.1234567` | reject | more than 6 decimals (lossy) |
| `01` | reject | leading zero |
| `00.5` | reject | leading zeros |
| `1.` | reject | trailing separator, no fraction |
| `.5` | reject | no integer part |
| `+1` | reject | sign |
| `-1` | reject | sign |
| `1e6` | reject | exponent |
| `1E6` | reject | exponent |
| ` 1` | reject | leading whitespace |
| `1 ` | reject | trailing whitespace |
| `1.2 ` | reject | trailing whitespace |
| `1\n` | reject | newline |
| `1,5` | reject | locale decimal separator |
| `1_000` | reject | thousands separator |
| `\uff11` | reject | fullwidth digit (no Unicode normalisation) |
| `\u0661\u0662\u0663` | reject | Arabic-Indic digits |
| `0\u0338` | reject | digit with combining slash |
| `1\u200b` | reject | zero-width space |
| `1\u200e` | reject | left-to-right mark |
| `` | reject | empty |
| `.` | reject | no digits |
| `1..2` | reject | double separator |
| `1.2.3` | reject | double separator |
| `0x10` | reject | hex |
| `NaN` | reject | not a number |
| `Infinity` | reject | not a number |
| `115792089237316195423570985008687907853269984665640564039457584007913129.639936` | reject | exceeds uint256 by 1 micro |
| `\x00` | reject | NUL byte |
