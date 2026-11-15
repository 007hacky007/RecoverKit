# Wordlist Library - Design

Date: 2026-11-16
Status: approved
Mockup: `docs/superpowers/specs/mockups/2026-11-16-wordlist-library.html` (open in a browser)

## Intent and why

Today a dictionary attack offers five built-in lists (Small and Medium English, numbers up to
99 / 999 / 9999), the `.txt` / `.dic` files at the top of the data folder, and a "..." button
that opens the system file picker. Anyone who wants a real password list has to find one,
download it, unpack it and point the wizard at it.

weakpass.com publishes 1,692 wordlists with a public, unauthenticated API that carries useful
metadata (rank, crack rate, word count, sizes, length distribution, character mix, common
patterns, sample passwords, MD5 checksums). The user wants RecoverKit to browse that catalog,
search and filter it, show the metadata, download selected lists, and use downloaded lists in the
dictionary settings next to the built-in lists and custom files.

## Goals

- A "Choose wordlist" dialog, opened from the "..." button next to each dictionary on the
  wizard's Dictionary settings page, with four tabs: Built-in, Downloaded, weakpass.com, File on
  disk.
- The weakpass.com tab lists the whole catalog with search (name), filters (rank S-F, size
  limit, minimum crack rate) and sortable columns, and a details column on the right for the
  selected list.
- Downloading a list: progress, speed, time left, resume after interruption, checksum check,
  unpack to a plain text file, then the list is ready to use.
- "Download and use" / "Use this wordlist" / "Use this file" fills the dictionary field the
  dialog was opened for.
- Downloaded lists also appear in the dictionary dropdowns.
- The File on disk tab keeps today's behaviour (system file browser) and adds a path field,
  file details, recently used files and the data folder's files.

## Non-goals

- No separate menu item or window for the library (decided: option B, dialog only).
- No torrent downloads (the API offers `torrent_url`; not used).
- No use of weakpass's other API endpoints (hash search, range lookup, rule generation).
- No changes to how attacks read dictionaries.

## Anti-goals (a failure even if it works)

- Contacting weakpass.com without the user opening the weakpass.com tab or clicking Refresh /
  Download. Opening the wizard or the dialog on another tab sends nothing.
- A partly downloaded, corrupt or partly unpacked file that can be selected as a dictionary.
  A list is usable only after both checksums pass.
- Deleting or overwriting any file the user did not download through the library.
- Filling the disk: a download that cannot fit (compressed plus unpacked during unpacking) must
  not start.
- Blocking the UI thread on network, unpacking, hashing or line counting.

## Approaches considered

1. **Download the whole catalog once and filter in the app (chosen by the user).** 17 requests
   of 100 entries (about 60 KB each). Cached on disk; search, filters and sorting are local and
   instant, any column can be sorted (the API's order is fixed: rank, crack rate, count), and the
   Downloaded tab works offline. Details are fetched per selected list.
2. Query the API on every search or filter change. Always current, but a request per keystroke,
   paging, fixed sort order, and no "time for this file" sort.
3. Live queries with a cache in front. More moving parts than 1 for no benefit.

The user added: the cached catalog acts as a cache, the dialog has a Refresh action, and the
catalog refreshes automatically when it is too old.

Layout: three were mocked up (a separate library window, this dialog, a card catalog). The user
chose the dialog with tabs, plus a details column on the right for the selected list, download
speed during downloads, and a file browser on the File on disk tab.

## The weakpass API (verified 2026-11-16)

Base `https://weakpass.com/api/v1`, OpenAPI at `https://weakpass.com/openapi.json`. No key.

- `GET /wordlists?per_page=100&page=N` - page of `Wordlist`:
  `id, name, slug, size (unpacked bytes), size_compressed, count (passwords), rank (S..F or
  null), rate (crack rate %, 0-100), download_url, torrent_url, url`. Page envelope:
  `data`, `links {first,last,prev,next}`, `meta {current_page,last_page,per_page,total,...}`.
  Pages past the last return an empty `data`. 1,692 entries in 17 pages at the time of writing.
- `GET /wordlists/{slug}` - `{ data: WordlistDetail }`: everything above plus `description`
  (may contain HTML, e.g. an `<a href>`; may be just a URL), `checksum` (MD5 of the unpacked
  file), `checksum_compressed` (MD5 of the downloaded file), `downloaded` (count),
  `created_at`, `updated_at`, `examples` (sample passwords, about 100), `masks`
  (`[{mask:"ld", count}]`, character classes l/u/d/s), `top_masks` (`[{mask:"?l?l?d", count}]`),
  `length_distribution` (`[{length, count}]`). Fetching details does not count as a download.
- `download_url` is `https://weakpass.com/download/<id>/<file>.gz|.7z` and redirects (302) to
  `https://download.weakpass.com/wordlists/<id>/<file>`, which supports HTTP Range (206) and
  sends ETag / Last-Modified.
- Formats: 1,558 `.gz`, 134 `.7z`. The `.7z` files checked (ignis-10K, hashmob micro,
  russkiwlst 10k) are single-file, non-solid, LZMA2. Both MD5 checksums were verified against
  real downloads (ignis-10K.txt.7z and rockyou-65.txt.gz).
- Sizes: 1,194 lists under 10 MB, 218 from 10 to 100 MB, 137 up to 1 GB, 75 up to 10 GB,
  68 above 10 GB; the largest is rockyou2024.txt at 156 GB unpacked (43 GB download).
- Ranks: F 1,252, E 172, D 106, C 70, B 43, A 28, S 21.

## Design

### Catalog cache (Core)

- Fetch all pages (`per_page=100`, follow until `next` is null or `data` is empty), sequentially.
- Store as JSON in `Settings.AppDataDir/wordlists/catalog.json` with the time it was fetched.
  Write to a temp file and move into place; a failed refresh keeps the old cache.
- Opening the weakpass.com tab shows the cache immediately. If it is older than 24 hours, or
  there is none, refresh in the background and replace the list when it arrives (keep the
  selection by `id`). The tab shows "Updated 3 h ago" and a Refresh button.
- No cache and no network: say so in the list area with a Retry button. Cache present and
  refresh failed: keep showing the cache and a short note ("Could not refresh: <reason>").
- Details (`/wordlists/{slug}`) are fetched when a list is selected, after a short debounce,
  and cached on disk by `id`. A cached detail is reused while it is younger than the catalog
  cache; a catalog refresh makes them stale.
- One `HttpClient` with the generic User-Agent `RecoverKit/<version>` (as `AppUpdater` and
  `HashcatInstaller` do). No personal data in requests.

### Filtering and sorting (Core, unit-testable)

- Search: case-insensitive substring of the name.
- Rank chips S, A, B, C, D, E, F (multi-select; none selected = all). Default: S, A, B.
- Size limit on the unpacked size: up to 10 MB / 100 MB / 1 GB (default) / 10 GB / any.
- Minimum crack rate: any (default) / 5% / 10% / 15% / 20%.
- Show downloaded lists in the weakpass.com tab too, marked "Downloaded".
- Sortable columns: Name, Rank, Cracks, Words, Download (compressed size), Time for this file.
  Default order: the API's (rank, crack rate, count descending).
- The footer shows "92 of 1,692 lists". Paging in the mockup is optional; a virtualised list of
  all matches is fine.

### "Time for this file"

The wizard already measures or takes a speed ("@ speed" on the Dictionary settings page) and
counts rules. Time = word count x number of rule outputs per word for the selected rules set /
speed. Show it only when it can be computed for a single-dictionary rules set; leave it empty
otherwise (two- and three-word rules, unknown speed). The details column says what it assumed:
"55 s at 18,236 p/s, rules "as is"".

### Details column

Title and rank badge; source / description (HTML stripped to text, links clickable); words;
cracks ("7.9% of weakpass test hashes"); download size and format; size on disk and free space
on the library drive (warning colour when it will not fit); time for this file; times
downloaded and last updated; password lengths bar chart (lengths 4 to 16 and "17+" summed; a
one-line summary such as "Most passwords are 6 to 10 characters (88%)"); character mix (from
`masks`, top five as bars with percentages, classes named in words); most common patterns
(`top_masks`, top four with percentages); sample passwords (first eight `examples`); "Open on
weakpass.com" link. While details load, show the catalog fields and a small loading note.

### Downloads (Core service, App-wide)

- One download at a time, others queued. The download service lives for the app's lifetime,
  so closing the dialog does not cancel; the Downloaded tab and the dialog's bottom bar show
  queued and active downloads. Cancel removes the partial file.
- Before starting: free space on the library drive must hold the compressed size plus the
  unpacked size plus a margin; if not, refuse with the numbers. Above 10 GB unpacked, ask to
  confirm, stating the download and unpacked sizes.
- Download to `<library>/<id>-<file>.part`, following the redirect. Resume with `Range` from
  the `.part` length when the server answers 206; restart from zero on 200. Report bytes,
  speed (moving average over a few seconds) and time left.
- Verify MD5 of the downloaded file against `checksum_compressed`. Mismatch: delete, report.
- Unpack: `.gz` with `GZipStream`; `.7z` with the existing 7-Zip header parser and LZMA/LZMA2
  decoder (`SevenZipExtractor`, `SevenZipLzma`) for single-file, unencrypted archives. Any
  other coder (PPMd, BZip2, BCJ, encrypted, several files) fails with a plain message naming the
  list and the reason. Unpack to a temp name, verify MD5 against `checksum`, then move to the
  final name. Delete the compressed file afterwards.
- Unpacked file name: the list's `name` sanitised for the file system (keep the extension it
  has; lists without an extension such as `b0n3z` get `.txt`). Collisions get the `id` added.
- A manifest `<library>/library.json` records for each downloaded list: id, name, slug, file
  name, rank, rate, count, size, checksum, downloaded at. The Downloaded tab and the dropdowns
  read the manifest; a manifest entry whose file is missing is dropped.
- Library folder: `<data folder>/wordlists` when the data folder is set in Preferences,
  otherwise `Settings.AppDataDir/wordlists`. The catalog cache always stays in AppDataDir.
- Delete (Downloaded tab) removes the file and its manifest entry after a confirmation.
  "Show in folder" reveals the file.

### The dialog (App)

- Opened from each dictionary row's "..." button; title "Choose wordlist for: Primary
  dictionary" (or "Dictionary #2" etc.). It opens on the tab that matches the field's current
  value (built-in name, downloaded list, file path); with an empty field it opens on the last
  used tab, or Built-in the first time.
- Built-in tab: the five lists with word counts and a one-line description each.
- Downloaded tab: rank, words, size on disk, Show in folder, Delete, and active / queued
  downloads with progress and speed; footer shows the folder and space used.
- weakpass.com tab: as above. Primary button "Download and use" (or "Use this wordlist" when
  already downloaded). While a download for the chosen list runs, the button shows progress;
  when it completes and the dialog is still open, the field is filled and the dialog closes.
- File on disk tab: path text box and "Browse..." (system file browser via `Pick.Open`, filters
  `*.txt;*.dic;*.lst` and All files, starting in the last dictionary folder); details for the
  chosen file (words via `Wordlists.CountLines` in the background, size, encoding via
  `Wordlists.Detect`, time for this file); recently used files (new setting, last 10, missing
  files dropped); the data folder's `.txt` / `.dic` / `.lst` files. Primary button "Use this
  file".
- A credit line on the weakpass.com tab: "Wordlists and statistics from weakpass.com".
- Theme: follows the app's light / dark palette (`Palette`), like the other windows.
- The dropdowns stay editable as today; their items become: built-in lists, downloaded lists
  (display name, e.g. "ignis-1M.txt (downloaded)"), then data folder files. Selecting a
  downloaded list stores its full path, so attacks, scenarios and saved settings need no new
  reference type.

### Errors and edge cases

- Network errors, HTTP errors, timeouts: plain messages; the catalog keeps the cache.
- A catalog entry with a null `download_url`: shown, Download disabled with a note.
- Rank null: shown as "-", sorted last.
- The app closes during a download: the `.part` stays and resumes on the next Download of the
  same list; stale `.part` files older than 7 days are deleted when the library opens.
- Very large lists: counts and sizes are 64-bit everywhere.

## Testing

- Unit tests with recorded API JSON fixtures (no live network in the default run): catalog
  paging and parsing, cache age logic and failed-refresh fallback, filters and sorting, detail
  parsing, HTML stripping, file name sanitising, manifest load / save / missing file.
- Downloader against a local test server (or an `HttpMessageHandler` fake): redirect, resume
  with 206, restart on 200, checksum mismatch on either file, cancel, free-space refusal.
- Unpack: `.gz` and `.7z` fixtures (small, single-file LZMA2 7z committed as test fixtures, or
  generated in the test), rejection of an unsupported 7z coder with a plain message.
- An optional live test (Category=Slow or a separate category) that fetches one catalog page and
  downloads `ignis-10K.txt.7z` (38 KB) end to end.
- Debug snapshots (`Ui/Snapshots.cs`) for each tab in light and dark, with fixture data.
- Default `dotnet test` passes on macOS and on the Windows VM.

## Left to the builder

Class names and file layout, the exact debounce and moving-average windows, whether the list is
paged or virtualised, how the details chart is drawn (Avalonia shapes are fine), and the exact
wording of messages within the tone of the rest of the app (plain, short, no jargon).
