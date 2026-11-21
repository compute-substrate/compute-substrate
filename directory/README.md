# Directory

Every site a `.csd` name points to, ranked by the people who recommend them. Nobody keeps the
list: the page reads it from the network through any door, and checks each site's title and icon
against the site's own address. Doorway shows the same list under *Discover*.

- **Listed:** any name whose profile points to a site (`contenthash`, `ipfs://<CID>`).
- **Recommended:** a record under the topic `csd.sites`. The first person to recommend a site
  writes a record whose text is its name (0.25 CSD); everyone after attests to that record
  (0.05 CSD). A key counts once per site. Recommending is signed by a key kept in the browser, with
  the welcome pool, invites and the USDC top-up for getting the CSD, as in the kit's template.
- **Faces:** a site's `<title>` and icon, fetched from a door one file at a time
  (`/sites/<cid>.car?path=…`) and checked block by block.

- **Links to a site:** the page's address with `#<name>` opens that name's newest site, on any
  device, phones included, with nothing installed. *Share* on each site makes one (through the
  phone's share sheet where there is one). Without Doorway, sites open through an IPFS gateway,
  which serves them unchecked; with Doorway, they open from the person's own computer, checked.

Its code is `src/page.ts` (the page) and `app/resolver/src/directory.ts` (the list, shared with
Doorway).

## Build and publish

```bash
cd kit && npm ci && cd ../app/resolver && npm ci && cd ../../directory
npm run build        # out/
```

Then *Publish* `out/` in Doorway and point a name to it. Anyone can host a copy: it's the same list
wherever it's served from.
