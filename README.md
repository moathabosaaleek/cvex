# cvex

A terminal dashboard for CVE feeds and security news. One panel instead of ten tabs.

## Status

Early. Doesn't do anything useful yet.

## Why

Every morning: NVD, CISA KEV, Krebs, BleepingComputer, a few RSS feeds. Ten tabs
to find the two things that actually matter today.

cvex puts them in one list and sorts by whether something is being exploited
rather than by CVSS. A 9.8 with no working exploit can wait. A 7.5 sitting in KEV
with a public PoC cannot.

macOS and Linux. One binary, local SQLite, works offline after the first sync.

## Not

- a scanner
- a replacement for a real threat intel feed
- multi-user. no accounts, no server, nothing to post to

## License

MIT
