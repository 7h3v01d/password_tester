# Optional lists

Anything here is loaded in the background at startup.

- `passwords/*.txt` — one password per line. Feeds the "commonly used password" check.
  A good start: SecLists `Passwords/Common-Credentials/10-million-password-list-top-100000.txt` (MIT).
- `words/*.txt` — one word per line (diceware `11111<tab>word` format is fine). Feeds the dictionary
  the scorer uses to spot words. The EFF large wordlist (CC BY 3.0 US) is a good fit.

The built-in dictionary is only ~340 words, so without lists here ordinary words like "wallstreet"
are scored as if they were random characters.
