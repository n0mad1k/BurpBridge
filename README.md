# BurpBridge

A Burp Suite extension (Montoya API) that adds a **BurpBridge** suite tab and a
localhost control API, so external tooling can drive Burp's own engine. Requests
issued through it use Burp's session handling and upstream proxy and appear in
Proxy history / Logger.

## Suite tab
Adds a "BurpBridge" tab in Burp with:
- Enable/disable toggle for the control API.
- Optional access token (when set, callers must send `X-Bridge-Token`).
- Clear Repeater and Dump Swing tree buttons.
- A live log.

## Control API (127.0.0.1:8737)
Access-gated by the enable toggle and, if set, the `X-Bridge-Token` header
(except `/ping`).

- `GET  /ping` - health check.
- `GET  /debug` - dump Burp's Swing JTabbedPane tree (for locating Repeater).
- `POST /clear` - clear Repeater tabs (Swing-based; see notes).
- `POST /send?host=H&port=443&tls=1&httpmode=&connid=` - body is a raw HTTP
  request; sends it through Burp and returns the raw HTTP response, prefixed with
  `X-Bridge-Elapsed-Ms` and `X-Bridge-Response` lines (a null/timeout response is
  reported, which is the key signal in desync timing tests). `httpmode` forces the
  wire protocol: `1`=HTTP/1.1, `2`=HTTP/2, `2ia`=HTTP/2 ignore-ALPN, `auto`/empty
  =negotiate. `connid` (any string) sends over a named reused connection, so a
  sequence of `/send` calls sharing one `connid` share a connection - used for
  single-connection request-smuggling victim tests.
- `POST /repeater?host=H&port=443&tls=1&name=Tab` - push a raw request into a
  named Repeater tab.
- `POST /scan?host=H&port=443&tls=1` - start an active audit on the raw request;
  returns an audit id.
- `GET  /scanstatus?id=scanN` - audit status, request/error counts, issues.
- `GET  /issues` - all scanner issues in the site map.
- `GET  /scope?action=include|exclude|check&url=U` - manage/query Burp scope.
- `GET  /sitemap?n=50` - recent site map entries.
- `GET  /history?n=30&match=SUBSTR` - Proxy history summary (method, URL, status),
  one row per entry prefixed with its absolute index `#i`. Scans newest-first and
  stops after `n` matches, so `match` stays fast on very large project histories.
- `GET  /historyfull?match=SUBSTR&n=3&maxbytes=32768` - full raw REQUEST and
  RESPONSE for matching Proxy history entries (headers included; each message
  capped at `maxbytes`). Use `i=INDEX` instead of `match` to fetch one specific
  entry by its `#i` index from `/history`. This is how to read what actually went
  over the wire (headers, cookies, tokens, bodies) rather than just a summary.
- `GET  /historyreq?match=SUBSTR` - raw REQUEST only, first (newest) match
  (kept for compatibility; `/historyfull` supersedes it).

`tls` defaults to 1 (HTTPS); set `tls=0` for plain HTTP.

## Build
Requires a Burp install (uses its bundled JDK and the Montoya API in
`burpsuite.jar`):

    ./build.sh          # or: BURP=/path/to/BurpSuite ./build.sh

Produces `BurpBridge.jar`.

## Load
Burp: Extensions > Installed > Add > type Java > select `BurpBridge.jar`.
To update after a rebuild: select the extension and Reload.

## Notes
- Repeater clear/group are not in the documented Montoya Repeater API; they are
  done by reaching Burp's Swing frame via `swingUtils().suiteFrame()`. Use
  `/debug` to map the tree; clear/group target that structure.
