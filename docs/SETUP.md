# First run, step by step

A guide for someone who has not worked with the Telegram API before. You will need
access to the support account: the phone on which it is logged into the official
Telegram app, and its two-step verification password if one is enabled.

## 1. What api_id and api_hash are and why you need them

Telegram lets third-party programs act on behalf of a regular account through its
API. So that Telegram knows which program is calling, every program gets a pair of
keys: `api_id` (a number) and `api_hash` (a 32-character string). They are issued for
free at my.telegram.org to any account owner. This has nothing to do with bots or
BotFather; no bot is involved.

The keys are tied to the phone number you obtained them with, so you must log into
my.telegram.org **with the support account's number**. One number can have only one
application (one pair of keys), which is all you need.

`api_hash` is a password-level secret. Do not publish it, show it in screenshots or
put it into git. In this project it lives only in `.env`, which is already gitignored.

## 2. Get api_id and api_hash

1. Open https://my.telegram.org in a browser. Preferably without a VPN and not from a
   corporate network behind a proxy: the site is picky and often answers `ERROR`
   because of that.
2. In **Your Phone Number** enter the support account's number in international
   format with a plus, for example `+12025550143`, and press **Next**.
3. Telegram sends the confirmation code **into the Telegram app** of that account (a
   message from the service contact named "Telegram"), not by SMS. Open the app on the
   phone where the support account is logged in, copy the code and enter it into
   **Confirmation code**. The code lives a few minutes.
4. After signing in, open **API development tools**.
5. If no application exists yet you will see the **Create new application** form:
   * **App title**: any name, for example `tg-collector`.
   * **Short name**: a short Latin name without spaces, 5-32 characters, for example
     `tgcollector`.
   * **URL**: can be left empty.
   * **Platform**: choose `Desktop` (or `Other`).
   * **Description**: can be left empty.

   Press **Create application**.
6. The next page shows **App api_id** (a number, e.g. `1234567`) and **App api_hash**
   (32 characters, e.g. `0123456789abcdef0123456789abcdef`). Copy both. You can open
   this page again later; the keys do not change.

If the site answers `ERROR` when you create the application, that is a known quirk of
my.telegram.org. What helps: wait an hour or two and retry, switch browsers, turn off
the VPN, remove everything unnecessary from the fields (only Latin letters and digits
in Short name, an empty URL). The keys are always free; there is no paid fast track.

## 3. Install the tool

You need macOS or Linux with Python 3.14 and [uv](https://docs.astral.sh/uv/). On
macOS:

```bash
brew install uv
cd tg-collector
uv sync
```

`uv sync` creates the `.venv` virtual environment and installs Telethon, the library
through which the program talks to Telegram.

## 4. Fill in .env

```bash
cp .env.example .env
```

Open `.env` in an editor and fill in:

```
TG_API_ID=1234567
TG_API_HASH=0123456789abcdef0123456789abcdef
TG_PHONE=+12025550143
TG_SESSION=data/session/support
TG_DATA_DIR=data
```

* `TG_API_ID`, `TG_API_HASH`: from step 2.
* `TG_PHONE`: the support account's number with a plus. Can be left empty; the program
  then asks for the number when logging in.
* `TG_SESSION`: where the session file (the authorization key) is stored. Leave as is.
* `TG_DATA_DIR`: the folder for all data. Leave as is.

## 5. Fill in config.toml

```bash
cp config.example.toml config.toml
```

A misspelled section or setting is refused with a message naming the closest real one
(`[anonymize] keep_term is not a setting; did you mean keep_terms?`), so a typo can
never turn a privacy setting off in silence.

For a first run four things matter:

* `[staff] sales`: colleagues in sales, so that their messages are labelled `sales`
  rather than client messages. `[staff] other`: the other employees who are members of
  client chats but mostly read along (managers, engineers). `[staff] support`: other
  support accounts, if any; the logged-in account is always `support`. The simplest
  way is to list their Telegram `@username`:

  ```toml
  [staff]
  support = ["@anna_support"]
  sales = ["@ivan_sales"]
  other = [123456789]
  ```

  Numeric ids are more reliable (a username can be changed or re-registered by a
  stranger). After the first export you can find them in `data/raw/users.json`, which
  lists `id`, name and `username` for every user, and replace the usernames with
  numbers. Everyone who is in no list is treated as a client; after `anonymize` the
  program points out who writes in three or more chats but is not in `[staff]`.
* `[anonymize] keep_terms`: the name of your product and company, for example
  `keep_terms = ["Northwind"]`. Every word of a chat title is treated as a client
  organisation's name and scrubbed from the text as `<org>`, so your product name
  (which usually sits in every chat title) is scrubbed too until it is listed here.
  Generic words such as `Банк`, `Групп`, `Технологии`, `Pay` or `Card` are never taken
  from titles, and neither are the feature words a title carries next to the client
  (`Ромашка — вебхуки`): `подключение`, `касса`, `вебхуки`, `возвраты`, `СБП`, `ККТ`,
  `прод`, `личный кабинет`, `checkout`, `sandbox` and the like stay in the text. A
  client whose name is one of those words needs `custom_terms`. A keep term protects the word on its own: a participant's full name or
  a `custom_terms` phrase that contains it is still removed as a whole. A multi-word
  keep term (`Northwind Pay`) is kept only as the whole phrase, so a surname that
  happens to be one of its words is still removed everywhere else. It does not
  protect a host that merely contains it (`northwind.client-shop.ru` becomes
  `<domain>`), nor a username (`@northwind_ivan` still becomes `@U#####`); only
  `northwind.ru`-style hosts made of the keep term and a suffix stay. A keep term
  that spells a whole handle (`payments`, a public chat's username that is also an
  API word) does keep that bare word, while `@payments` and its `t.me` link are
  replaced either way. Keep terms are compared case-insensitively, with ё/е folding
  and with invisible characters and stray blanks removed, so a term pasted out of a
  chat still matches.
  Never put a client's name into this list.
* `[anonymize] allow_domains`: your own hosts and public sites whose links should stay,
  for example `allow_domains = ["docs.example.com", "*.example.com"]`. An exact entry
  keeps only that host; `*.example.com` keeps every host under it with the subdomain
  hidden (`<sub>.example.com`). Passwords, tokens, tax ids, redirect targets and
  client names inside a kept link are still removed, including the percent-encoded
  ones a browser writes (`?q=%D0%9F%D0%B5%D1%82%D1%80%D0%BE%D0%B2` is a surname).
* `[anonymize] card_bins`: the BINs (first 6 digits) of your product's cards, for
  example `card_bins = ["424242", "400000"]`. Any card number in a message becomes
  `424242**********` (only the BIN stays); cards with the listed BINs are recognised
  even when the number has a typo or the client has already hidden part of it with
  asterisks.

Everything else can stay as it is: the defaults are tuned for a gentle pace.

## 6. Log into the account (once)

```bash
uv run tg-collector login
```

What happens:

1. The program contacts Telegram with your keys, asks it to send a login code and then
   tells you **where** Telegram delivered it, for example:
   `Telegram sent the login code via the Telegram app on a device where this account
   is already logged in: open the chat named 'Telegram' (service notifications) and
   copy the login code.`
2. In the vast majority of cases the code does **not** arrive by SMS but as a message
   inside the Telegram app on a device where the account is already logged in. Open
   Telegram on the phone, find the chat named **Telegram** (the service chat with a
   blue check mark; it usually moves to the top of the list) and look for a message
   like "Login code: 12345". Type the code into the terminal.
3. If the code does not show up, type `resend` in the terminal: Telegram sends it
   another way (SMS, then a phone call; for a call the code is the last digits of the
   calling number). Telegram enforces a pause between resends, so do not type `resend`
   many times in a row: that earns a temporary login block.
4. If the account has two-step verification (a cloud password), the program asks for
   that password. The characters are not echoed while typing; that is normal.
5. At the end you see a line like `Logged in as Name (@username) id=...`.

If the code does not arrive by any method: the account must be logged into the
official app on at least one device. Log in there the usual way (by SMS); after that
codes for the program arrive in the app.

### Login with a QR code (no code at all)

If SMS is unreachable and the code does not arrive in the app, log in with a QR code,
the same way Telegram Desktop is linked:

```bash
uv run tg-collector login --qr
```

A QR code appears in the terminal. On the phone with the logged-in account open
**Settings -> Devices -> Link Desktop Device** and scan it with the camera from that
screen. The code lives about 30 seconds; if you miss it, the program draws a new one,
nothing needs restarting. If a cloud password is enabled, the program asks for it
after the scan. You can also type `qr` when the regular `login` asks for the code.

The terminal needs a monospaced font (the standard Terminal or iTerm are fine);
enlarge the window if needed so the whole code fits, and do not zoom while scanning.

After login, `data/session/support.session` holds the authorization key. It replaces
the code and password in all later runs, so keep it like a password and do not copy it
to other machines. In the Telegram app, under **Settings -> Devices**, a new session
named `tg-collector` appears: that is this program. Do not terminate it, or you will
have to log in again.

If Telegram answers that a wait of N seconds is required, there were too many login
attempts in a row: wait the stated time and retry.

## 7. See which chats will be exported

```bash
uv run tg-collector chats
```

The program requests the list of all dialogs once and says for each one whether it
will be exported and why. Example (fictional titles):

```
INCL  ID               KIND         MEMB  TITLE                  REASON
yes   -1001234567890   supergroup     14  Acme Ltd / Northwind   included
yes   -1009876543210   supergroup      6  Globex support         included (member list participants hidden)
-     -1005555555555   supergroup      4  Sales team             internal (all members are staff)
-     123456789        private             Ivan                   type private
-     -1007777777777   channel             Northwind news         type channel

2 of 5 dialogs selected for export
```

`INCL` is `yes` for chats that will be exported. `REASON` explains the decision:
`included`, `type private` / `type channel` (kind not in `include_types`),
`internal (all members are staff)`, `excluded by id`, `not in include_ids`,
`archived`, `title matches exclude_title_regex`, `no access (left/forbidden)`,
`merged into <id>` for a legacy group that follows its supergroup.

Check the table. If a non-client chat made it in, add its `ID` to
`[chats] exclude_ids` in `config.toml`. If a chat you need is marked internal, it has
no members other than `[staff]`: check the staff lists. One-to-one dialogs and
channels are not exported by default; that is expected.

To export only some of the chats, use `include_ids`.

With many dialogs the table takes a while: the program checks the members of every
chat that passes the filters, with a pause between requests, and prints a line for
each chat it asks about (`[12/310] members of supergroup 'Acme support' (-1001234567890)`).
What it fetched is saved, so running `chats` again after editing
`config.toml`, and the `run` that follows, reuse it for 24 hours instead of asking
Telegram again (`--refresh` asks anew).

## 8. Export, anonymize, verify

```bash
uv run tg-collector run
```

This is `export`, `anonymize` and `verify` in a row. The first export is slow on
purpose, with pauses between requests, so that the account does not look suspicious.
Hundreds of chats take hours; large archives take up to several days. Progress is
printed per chat. You can interrupt the run (Ctrl+C) and repeat it: only new messages
are fetched.

Result:

* `data/anon/dataset/`: the anonymized dataset; this is the folder you can pass on.
  Start with `data/anon/dataset/chunks/`.
* `data/raw/`: the raw export with real identifiers. Never share. Keep it until
  `verify` has run: the audit hunts for the identifiers it holds, and without it
  `verify` stops instead of reporting a clean dataset.
* `data/anon/mapping.json`: the link between virtual and real ids. Never share.
* `data/anon/anonymize_report.json`: what was scrubbed, how often, with samples. Have
  a look: if product feature names or error codes are being scrubbed, add them to
  `keep_terms` and re-run `uv run tg-collector anonymize`.

Everything under `data/` can be read by your user account only (files have mode 600,
folders mode 700). At every start the program also closes `data/raw/`, `data/anon/`,
`data/session/` and the session files themselves to other users, in case an older
version left them readable; the folder `TG_DATA_DIR` names keeps its own mode, since it
may be your home or project directory. `.env` is yours to protect: run `chmod 600 .env`
once, the program never writes that file. To hand the dataset over, copy
`data/anon/dataset/`.

`verify` reads every file under `data/anon/dataset/`, including any you added
yourself, so remove your own notes from that folder before an audit or expect them to
be scanned too.

If `verify` reports possible leaks, they are often false positives (a last name that
coincides with an ordinary word, for example). Open `data/anon/verify_report.json`,
look at the matches and either add the word to `keep_terms`, or add a real leak to
`custom_terms` / `custom_patterns`, then run `anonymize` and `verify` again. A
`custom_patterns` entry replaces its whole match, so match the value alone to keep the
keyword as product knowledge (`'(?<=КПП\s)\d{9}'`, not `'КПП\s*\d{9}'`); it also wins
over a `keep_terms` word inside its match, and a pattern that could match the empty
string is refused at load time (write `\d{9}` or `\d+`, never `\d*`). The
matches quote raw data, on the console as well as in the report: redact them before
pasting anything into an issue or a chat.

After `anonymize` the console lists people who write in three or more client chats
but are not configured in `[staff]`. Usually these are colleagues: add them to the
config and re-run `anonymize`. It also lists the chat-title words it scrubbed as
`<org>`: if a product word is among them (`billing`, `карты`), add it to `keep_terms`.
Words found in the titles of many chats are printed separately ("Words found in the
titles of many chats were scrubbed as <org> everywhere"): this is usually your product
name, but it can also be a client with several chats, so the program never keeps it on
its own. If the word is your product or company, add it to `keep_terms` and re-run
`anonymize`; if it is a client, leave it scrubbed.
In `anonymize_report.json`, the `top_surfaces` section shows which words the name and
organisation rules replaced most often; a common word high in that list is a
candidate for `keep_terms` as well. Its `domain` list shows the bare hosts scrubbed
most often: a public site that fires often (a marketplace, a search engine) can go
into `allow_domains`; never add a client's site.

## 9. Repeat runs

Just run `uv run tg-collector run` again. Virtual ids are preserved and only new
messages are fetched. Do not run two copies at once (the program refuses to work when
the session is busy) and do not move the `.session` file to another computer.

## 10. Takeout mode (optional, for the first big export)

In `config.toml` you can enable `[export] takeout = true`. History is then read
through Telegram's official "Export Telegram data" mechanism, which has softer limits
on reading. On the first run Telegram notifies all of the account's devices about the
export request and asks you to confirm it in the official app (a message with a button
appears there) or to wait up to 24 hours. The program then exits with
`STOPPED: Telegram requires confirmation of the data export ...`; confirm the export on
the phone and start again. The export session is remembered, so later runs do not ask.

## Common errors

| Message | What to do |
|---|---|
| `Config error: Missing Telegram credentials` | `.env` is not filled in, or it is not in the project directory (see `--project`). |
| `Session is not authorized. Run: tg-collector login` | You have not logged in yet, or the session file was deleted. |
| `another tg-collector process is using ...` | Another run is in progress. Wait for it or stop it. |
| `STOPPED: Telegram asked to wait N seconds ...` | Telegram requested a pause longer than two hours. Run again the next day; the export resumes. |
| `STOPPED: Telegram limited the account ...` | The account is restricted. Open @SpamBot in the app to see the reason; do not run the program until the restriction is lifted. |
| `STOPPED: Telegram requires confirmation of the data export ...` | Takeout mode: confirm the export in the official app, or wait the stated time, then run again. |
| `The session was invalidated ...` | The session was used from two places at once. Log in again with `login`, from one machine only. |
| `ABORTED: N raw identifiers survived scrubbing` | The anonymizer's self-check found a real id, username or phone in the output. Report it as a bug (the line itself quotes nothing: the raw values stay in `data/anon/anonymize_abort.json`); do not share the dataset. |
| `Mapping error: ... is corrupted ...` | `data/anon/mapping.json` is not readable as a mapping. Restore it from a backup, or delete it and re-run `anonymize` — the virtual ids of every chat and user will then be new. |
| `Mapping error: all N virtual ids ... are taken` | The id space of this mapping is full. Start a new mapping (move the file away); the new dataset gets fresh ids. |
| `No raw export found in ...; verify needs it` | `verify` hunts for the identifiers of `data/raw/`. Re-export, or run `verify` before deleting the raw export. |
| `ERROR` on my.telegram.org | Retry later, without a VPN, from another browser. |
