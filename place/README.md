# doorway.place

Doorway's own home: download it (the newest release, for the visitor's computer first), look up a
`.csd` name and see where it points and how long its site is kept up, point a name at a site and
add a year (signed in Cairn Wallet by the key that holds it), and browse the sites on the network.

It's a static page with nothing behind it. Everything it shows is read through the network's
doors and checked in the visitor's browser, with the same code Doorway uses (`app/resolver`). If
the domain went away, every name and site would still work through Doorway.

```bash
cd place && node build.mjs      # then upload out/ (Cloudflare), or publish it with Doorway too
```

Links to a name are `https://doorway.place/#<name>`: they look the name up and offer to open it in
Doorway. The directory shares sites this way.
