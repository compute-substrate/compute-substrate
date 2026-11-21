# The front page

Compute Substrate's own front page, as a site on the network: no server, opened at
`computesubstrate.localhost` with Doorway, and kept up by keep records anyone can add to. Its numbers
are read from the network in the visitor's browser and checked there: the height (every header since
the release's anchors, by proof-of-work), the doors that answer, the sites, and how long the page
itself is kept up, with *Add a year* for anyone. computesubstrate.org stays as it is.

## Build and publish

```bash
cd kit && npm ci && cd ../app/resolver && npm ci && cd ../../home
npm run build        # out/
```

The release attaches it packed, as `home.car`. In Doorway: *Publish*, choose that file, and point
the name `computesubstrate` to it. Then keep it up with the hourglass, for as long as you like.
