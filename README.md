# Store sales app

Static, AES-256-GCM encrypted page (PBKDF2-SHA256, 600k iterations). The repo holds only ciphertext; the browser decrypts with the password.
Serve with GitHub Pages (Settings > Pages > Deploy from branch > main / root).

## One password, both pages

`tools/build-integrated.mjs` merges the store sales page and the 2027 EBITDA simulator into one encrypted payload behind one password. After unlock, a tab bar switches between the two pages (deep links: `/#sales`, `/#scenario`; `/scenario` redirects to `/#scenario`). Run it from the repo root with Node 18+; see the header of the script for the exact commands. Passwords are read from environment variables and are never written to disk.
