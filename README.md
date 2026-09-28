# tg-collector

Read-only Telegram chat collector. It logs into a regular Telegram user account (a
company's support account, not a bot), exports the history of the client group chats
that account is a member of, anonymizes the text and builds a dataset that can be
handed to an LLM to write a product glossary or a knowledge base of typical support
requests.

The tool only ever reads, and it is deliberately slow: a full first export can take
hours or days, but the account never behaves like an abusive client. See
[Account safety](#account-safety) for what it does and does not do.

## What you get

`data/anon/dataset/` is the folder you can hand out:

* `chunks/chunk-001.md ...`: transcripts packed into files of roughly equal size
  (200,000 characters by default). Feed these to the model one at a time.
  `chunks/index.json` lists which transcript parts went into each chunk.
* `transcripts/C48137.md ...`: a readable transcript per client chat (split into
  `C48137.part01.md ...` when large), divided into **episodes**: runs of messages
  without a long pause, and within one forum topic. One episode is usually one
  request and its resolution.
* `messages.jsonl`, `episodes.jsonl`: the same data one JSON object per line for
  programmatic use. Messages are complete here; transcripts shorten long ones.
* `users.json`, `chats.json`: virtual users `U#####` and chats `C#####` with roles,
  sides, counts, periods and participants (sorted by virtual id).
* `manifest.json`: counts, date range, a snapshot of the anonymization policy, notes.
* `README.md`: a description of the format that can be pasted into the model's
  system prompt.

A transcript looks like this (all names fictional):

```
[2024-01-10 12:01] #3 CLIENT U12210 Ivan: Excel export fails with E1042, @U48941 please look
[2024-01-10 12:05] #4 STAFF U48941 Anna (support) ↳#3 U12210 "Excel export fails with E1042, @U48941 please look": Ivan, looking into it. Please send the log
[2024-01-10 12:06] #5 CLIENT U12210 Ivan: [document:log 34 KB] my phone is <phone> if you need it
```

`SIDE` is `CLIENT` (the customer), `STAFF` (the vendor: support, sales, admins),
`BOT` or `UNKNOWN`; a kept service message is written by `SYSTEM`. The role in
brackets is `support`, `sales`, `other` (colleagues who sit in client chats and mostly
read along), `bot`, `deleted` (the account is gone) or `anonymous admin`; clients carry
no role suffix. Replies quote the message they answer, on one line, with a line break
of the quoted message shown as `⏎`. Consecutive messages of one
sender within `turn_merge_seconds` (120 s) are rendered as one turn (indented `#seq:`
lines). Long messages are shortened in transcripts with `[... N chars omitted ...]`
(JSONL keeps them whole), and messages that are mostly code or logs are fenced.
A quote and a shortened message are cut at word boundaries, so no cut ever falls
inside a placeholder, a masked card or a number.

### What is removed and what stays

Removed: Telegram ids and usernames, of people and of the exported public chats (also
written without `@`, glued to a word, with a space after `@`, with a Russian case
ending that ends the word (`@ivan_petrovу`, but not `@ivan_petrovу2`, where the
ending belongs to another handle), or introduced by a keyword such as `skype`,
`инста`, `логин`), messenger and
chat ids by keyword, phone numbers in every spelling (national formats, digit by
digit, typographic dashes, dashes with spaces around them `8 (999) 123 - 45 - 67`, a
stray dot such as `8 999 123.45 67`, glued to `тел.`, bare numbers after a phone
keyword, a number standing inside a longer run of numbers `id 4521 999 123.45 67`, and
a participant's own number from their Telegram profile in any grouping at all),
IPv4 and IPv6 addresses (private ranges included),
e-mail addresses (also mistyped or obfuscated: `ivan.example
[at] mail [dot] ru`, `ivan.example собака mail.ru`, or wrapped over a line break at the `@`
when the local part is ASCII, as e-mail local parts are), links (also scheme-less
`instagram.com/handle`) and bare domains (in any case, `Ромашка.РФ`, `Acme.Ru`, also
at the end of a sentence; a host that merely contains a `keep_terms` word, such as
`northwind.client-shop.ru`, is removed too), identifiers inside a link that the policy
keeps (query values such as `?password=`, `?inn=` or `?code=`, user info such as
`postgres://app:secret@`, redirect targets, client organisation names in the path),
bank card numbers (only the BIN stays:
`424242**********`; your own BINs go into `card_bins` so those cards are caught even
with typos, missing spaces, hand-written masks or a line break; also glued into a file
name with `_`: `file_4000000000000002.pdf`), expiry date and CVV
next to a card (also as fields of a dump, `4242424242424242|12|27|123`, and after a bare
`до` or `код` in a message that carries a card number),
SMS / 3-D Secure / backup codes (also after the spellings clients type: `пароль из смс`,
`пин из смс`, `кодик`, and under a confirmation key such as `sms_code`, `confirm_code`,
`verification_code`), PINs, cardholder names (also surname
+ initials, and after `держатель карты` or a card product: `держатель карты Visa Gold
<cardholder>`), IBANs (checksum), bank routing / sort codes and account numbers, crypto
wallets (also a TON address glued to a word or cut short), transaction hashes and seed
phrases, `login:password:2fa` dumps, `user:password` pairs after a login flag or word
(`curl -u`, `--user`, `логин`, `акк`, `доступ`) and for default accounts
(`root:toor1234`), passwords (also labelled `пароль от личного кабинета:` and
`пароль для входа в личный кабинет:`, on the next
line, spelled `pw`, `пасворд`, `пороль`, written `с
паролем ...`, after a state word such as `пароль: новый ...`, after a filler word
(`пароль был Qwerty123`, `пароль у него ...`, `пароль сменил на ...`, `my password is
...`), as a bank's `кодовое слово`, followed by another
field such as `логин:`, `почта:` or a second
`пароль:`, inside quotes or JSON, as a quoted passphrase with spaces, under a code key
that ends in a secret word such as `"db_password"` or `'api_secret' =>`, or given as
`-p` on a command line), the text of an XML or SOAP element whose tag names a secret
(`<Password>`, `<wsse:Password>`, `<CVV2>`, `<ApiKey>`, `<Login>`; the markup stays),
2FA secrets
(also in groups of four), API keys with well-known prefixes (also the dotted SendGrid
key and Russian labels such as `токен доступа`, `апи ключ`), PEM private key blocks
(also pasted as one JSON string with literal `\n`), HTTP Basic credentials
(`Authorization: Basic ...`), `.env`-style assignments, cookies and access tokens,
long random tokens (also with `-`, `_` or `/` inside), long identifiers that hide a
phone, card, account or document number
(`client_79161234567_northwind_payment_report_2026.xlsx`,
`passport_4510_123456_ivanov_ivan_scan_final.jpg`) or name a secret
(`prod_secret_2024_merchant_northwind_backup_01`); in a short file name only the
number itself goes, and the words around it stay
(`client_<phone>_report.xlsx`, `скан_паспорт_<passport>.pdf`, `inn_<inn>.pdf`),
grouped licence keys after a licence word (`ключ активации VK7JG-NPHTM-C97JM-9MPGT-3V66T`,
`license key ...`; a bare group run and reference-shaped runs such as
`ACT-4001-DECLINED-CARD` stay), long identifier-shaped logins after a login, proxy or password
word (`логин customer-acmeltd-cc-RU-city-moscow-sesstime-10`) or in front of their own
password, which then goes with them
(`customer-acmeltd-cc-RU-city-moscow-sesstime-10:Pa55w0rd` becomes `<credentials>`),
proxy strings, user-agent strings (the text after them stays), Kazakhstan IIN/BIN and
Ukraine RNOKPP (with checksums), Russian INN/OGRN/SNILS, passports (also after `уд.л.`,
`уд. личности`, `удв`), driver licences (also after `вод. уд.`),
dates of birth (also after `д/р`, `день рождения`, `дата рожд.`), addresses and postcodes
by keyword (also after `по адресу` and `мой адрес`), expiry dates after `дата окончания`,
`срок карты` or `валидна до`, CVV after the Russian-layout `цвв`/`свв`, wallet addresses
glued to `кошелёк`, ad-platform account ids (`act_`,
BM, pixel, TikTok, Google Ads), exchange UIDs, RRN/ARN/authorization codes, last names
of participants (in every case form,
with ё/е folding, also inside file names, constants and logins), names written in the
first-name field ("Иван Петров" keeps only "Иван"), name + patronymic pairs (also in
capitals, `ПЕТРОВ ИВАН СЕРГЕЕВИЧ`), people named next to
a keyword (`меня зовут`, `фио`, `получатель`, `контактное лицо`, signatures, `ИП`, role
words; in capitals or lower case too), names of
client organisations (every significant chat-title word, generic words excluded, also
the old title of a merged legacy group, wherever it appears in message text), and the
headers and `[Forwarded from ...]` lines of messages copied from Telegram Desktop.

Kept: first names (by default only the first name, and only when it is shaped like a
name: nicknames such as `Vasya_Pupkin` are dropped, and so is a name that is a known
username, such as `Kotik` for `@kotik`), roles, timestamps, the reply structure,
ticket, order, transaction and payment numbers (also when one happens to pass a
tax-number checksum, and dashed order references after a coin keyword such as `usdt:
INV-20260312-000123`; a bare 13-19 digit number that passes Luhn is masked as a card,
see [Known residuals](docs/RESIDUALS.md)), error and decline codes (also after `cvv`,
`pin` or `срок`, and reference codes after `код` such as `код ответа 4001`, `код
товара 4001`, `Код ТСП`, `МСС код 5411` in either alphabet, or `код 4001 означает
...`; a decline code explained on its own line stays too, also in a list or a table
(`Код 4003 — карта заблокирована эмитентом`, `- код 4001: недостаточно средств`,
`| код 4001 | недостаточно средств |`, `падает с кодом 5003`), and in a glossary of
codes the keyword that ends one entry no longer takes the code that opens the next
one),
version numbers, amounts, dates, deadlines and durations (`срок до 12.03.2026`, `срок
10-14 дней`), four-part version and clause numbers shaped like an IP address
(`версия приложения 2.15.3.100`, `обновитесь до 2.14.0.3`, `APP_VERSION=1.2.3.4`,
`пункт 4.1.2.3`), loopback addresses (`127.0.0.1`, `0.0.0.0:8080`, `[::1]:8443`), columns of amounts
and dates (`1500.00 2300.50`, `сумма 1500.00 12.03.2026`; a phone word such as `тел` or
`звоните` right before still makes the run a phone), product feature names,
`ALL_CAPS_CONSTANTS` (a participant's name in one is still removed), constants,
settings and file names that a secret word is glued into (`ошибка PASSWORD_EXPIRED`,
`PASSWORD_MIN_LENGTH=8`, `password_min_length: 8`, `passwordMinLength`,
`password_reset_flow_v2`, `tokens_rotation_plan_v2.docx`), long error
constants, REST
paths, file names and campaign slugs made of words, numbers, versions and dates
(`PAYMENT_DECLINED_INSUFFICIENT_FUNDS_ERROR_4001`,
`/api/v2/merchants/12345/transactions/2026-03-12`, also after `token`,
`report_2026_03_12_final_version_v2_export.xlsx`, `offer-nutra-kz-2026-03-12-landing-v2`;
a whole path segment that is a phone, INN, IIN or account number, a known id or a
number after a document word still becomes its placeholder, while an unlabelled number
that no rule recognises stays there as it does in prose), chat-title words that
are product vocabulary (`API`, `карты`, `billing`, `v2`, `L2`, `1С`), and the words you
list in `keep_terms` (your product and company name). Command-line flags that are not
credentials stay too (`ssh -p 2222`, `mkdir -p /var/log`, `docker run -u 1000:1000`,
`postgres:16-alpine`), and so do the project, profile and git-ref arguments of a
command that has no password to give (`docker compose -p Northwind2 up`, `git log -p
HEAD~3`, `kubectl logs -p Pod1`; a login command on the same line still wins:
`docker compose -p Northwind2 exec db mysql -u root -p<password>`), as do JSON field
names after the word `ключ`, access levels, roles, scopes and versions after
`доступ`, `акк` or `учётка` (`доступ: role:viewer`, `права доступа:
payments:write_all`, `аккаунт: iOS:17.4`), the quotes and
brackets around a removed value (`{"password": "<password>"}`), validation and error
messages and outcome words in a password slot (`пароль: "не задан"`, `{"password": "не
менее 8 символов"}`, `пароль:` followed by `ошибка 4012` on the next line, `пароль:
неверный`, `Пароль Устарел`, `password: expired`, `{"password": null}`), password
policy and instruction prose (`пароль 8-64 символа`, `пароль: минимум 8 символов`,
`пароль: придёт отдельным письмом`, `пароль: только латиница`), a value that says
where the secret is kept instead of spelling it out (`SECRET_KEY="см. README"`,
`{"secret_key": "выдаётся менеджером"}`, `api_key: "храним в Vault"`,
`API_TOKEN=${API_TOKEN}`), settings in an XML element whose tag merely mentions one
(`<TokenType>Bearer</TokenType>`, `<PinRequired>true</PinRequired>`,
`<ExpirePassword>true</ExpirePassword>`), words that merely start with a
short keyword (`пинг 1500 мс`, `другая дата 12.03.2026`, `индексация`, `export`), rules and
questions after an address keyword (`прописка не нужна`, `адрес доставки можно изменить в
течение 24 часов`, `billing address must match the card`), counts after an address keyword
(`адрес регистрации: 2 страница паспорта`, `адрес доставки: 1-3 дня`, `адрес: до 255
символов`, `billing address: step 2 of 4`), card networks, tiers and banks
after a holder word (`для держателей Visa Gold`, `держатель карты Visa Platinum`,
`Cardholder Name Mismatch`, and after a plural holder word a two-word product name such as
`держатели карт Райффайзен Премиум`), a short lower-case word before a number after a document keyword (`права
на 1234567`, `заявка id 1234567`, `паспорт по 1234567`), `пер.` as shorthand for a transfer
(`пер. 1500 руб`, `пер. на карту 1500`), English phrases that merely end in a street word
(`2 cards by the way`), the `BEGIN`/`END` lines of a removed private key, dotted
product names whose suffix is an English word or a payment product (`Yandex.Money`,
`App.Store`, `Apple.Pay`), documentation files (`README.md`, `CHANGELOG.md`), your own
host when it is only a keep term or a keep term plus a suffix (`northwind.ru` with
`Northwind` kept), retina asset names and package versions next to `@` (`arr@2x.png`,
`lodash@4.17.21`), npm scopes in a package-manager command or a `node_modules/` path
(`npm i @types/node`), and the routes, ids and product values of a kept link
(`https://docs.example.com/errors/code/05?lang=ru`).

Placeholders keep the *kind* of data that was removed:

* people and contacts: `@U#####` (mention), `@C#####` (an exported chat named by its
  public username), `@user` (unknown mention), `<name>` (last names, full names,
  name + patronymic, people named next to a keyword), `<cardholder>`, `<email>`,
  `<phone>`, `<address>`, `<postcode>`, `<dob>`, `<org>`, `<domain>`, `<id>` (a raw
  Telegram chat or user id written out in the text, `-1001234567890` included)
* links: `<url>`, `<url:host>` (`<url:[::1]>` for an IPv6 host), `<tg-link>`, `<ip>`,
  `<proxy>`, `<user-agent>`, `<sub>` (the hidden subdomain of an allowed host:
  `<sub>.example.com`); a link kept by the policy carries placeholders where it held
  identifiers (`?password=<password>`)
* cards and payments: `424242**********` (BIN kept, rest masked; `<card>` when the BIN
  is unreadable), `<exp>`, `<cvv>`, `<pin>`, `<otp>` (SMS / 3-D Secure / backup code),
  `<iban>`, `<account>`, `<bank-code>` (routing / sort code), `<txn-ref>`
  (RRN/ARN/auth code)
* crypto: `<wallet>`, `<txid>`, `<seed-phrase>`, `<id>` (exchange memo / uid,
  messenger id, ad-platform id), `<ad-account>`
* documents: `<passport>`, `<driver-licence>`, `<iin>`, `<rnokpp>`, `<inn>`, `<ogrn>`,
  `<snils>`, `<tax-id>`, `<personal-id>`, `<company-id>`, `<device-id>`
* secrets: `<password>`, `<credentials>` (login:password pairs and dumps), `<2fa-secret>`,
  `<token>`, `<private-key>` (the body of a PEM block), `<cookie>`, `<redacted>`
  (custom patterns)

Keywords next to a value stay (`cvv <cvv>`, `IIN <iin>`, in Russian `ИИН <iin>`), so
requests can still be classified. Attachments appear as `[photo]`, `[document:pdf 1.2 MB]`, `[voice 0:41]`;
no files are included.

The link between virtual ids and real Telegram ids lives **separately** in
`data/anon/mapping.json` (file mode 600). Virtual ids are random and all have the same
width (five digits, fixed when `mapping.json` is created): they reveal neither the
order of appearance, nor the run that first saw a user or chat, nor the age of an
account. A conversation keeps one id across incremental runs even when a client
upgrades their group to a supergroup between two exports: the legacy group and the
supergroup share the virtual id the chat already had, so its history does not move to
a second id. A `mapping.json` written by an earlier version keeps its ids and its width
(four digits, at most 9,999 ids per prefix; a file that had already mixed four- and
five-digit ids keeps that history), so delete it and start fresh if a uniform width
matters more than stable ids. `dataset/` can be shared; `mapping.json`, the reports in
`data/anon/` and everything in `data/raw/` cannot.

## Requirements and installation

Python 3.14 and [uv](https://docs.astral.sh/uv/). The tool uses a file lock, so it
runs on macOS and Linux.

```bash
cd tg-collector
uv sync
cp .env.example .env                 # fill in TG_API_ID / TG_API_HASH from https://my.telegram.org
cp config.example.toml config.toml   # adjust [staff] and keep_terms at least
```

Both `.env` and `config.toml` are gitignored. In `config.toml` you need at least:

* `[staff] sales` and `[staff] other`: colleagues who are members of client chats
  (numeric user id preferred, `@username` accepted). Anyone not listed is treated as a
  client.
* `[anonymize] keep_terms`: your product and company names, so they are not scrubbed
  as a client organisation, e.g. `keep_terms = ["Northwind"]`.

The step-by-step guide for a first run, including how to get `api_id`/`api_hash` and
log in, is in [docs/SETUP.md](docs/SETUP.md).

## Usage

```bash
uv run tg-collector login       # once: login code from Telegram, 2FA password if enabled
uv run tg-collector login --qr  # alternative: scan a QR code in the official app
uv run tg-collector chats       # table of dialogs: what will be exported and why
uv run tg-collector export      # raw export into data/raw/ (incremental, safe to re-run)
uv run tg-collector anonymize   # data/raw -> data/anon/dataset + mapping.json
uv run tg-collector verify      # leak scan of the dataset; non-zero exit if anything was found
uv run tg-collector run         # export + anonymize + verify
```

Options:

* `export --full` (also `run --full`): re-export the selected chats from scratch, to
  pick up edits and deletions of old messages. By default only new messages are
  fetched.
* `export --only ID ...` (also `run --only`): only these chat ids (see `chats`).
  A legacy group merged into a selected supergroup follows it.
* `--project DIR`: directory with `.env` and `config.toml` (default: the current
  directory). Relative `TG_DATA_DIR` and `TG_SESSION` paths resolve against it.
* `--config PATH`: an explicit `config.toml` (default: `<project>/config.toml`).
* `-v`, `--verbose`: debug logging.

A section or setting `config.toml` does not know is a configuration error naming the
closest real one (`[anonymise] is not a config section; did you mean [anonymize]?`,
`[anonymize] keep_term is not a setting; did you mean keep_terms?`). A typo would
otherwise leave a privacy switch at its default without a word, and the run would keep
in the dataset exactly what you meant to remove.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Configuration error; nothing to work on (no raw export for `anonymize` or `verify`, no dataset for `verify`); or `mapping.json` is unusable (`Mapping error: ...`: corrupted, or its id space is exhausted). |
| 2 | The run was stopped (`STOPPED: ...`): session problem, account limited, takeout confirmation pending, flood wait above the ceiling; some chats failed during `export` (re-run `export` to resume); or the command line was invalid (argparse usage error). |
| 3 | The anonymizer's self-check found a real identifier in the output (`ABORTED: ...`). The line names the kind and the virtual location of each hit; the raw values go to `data/anon/anonymize_abort.json` (private, mode 600). |
| 4 | `verify` found possible leaks; see `data/anon/verify_report.json`. |
| 130 | Interrupted with Ctrl+C. The export cursor is saved; re-run to continue. |

`run` executes `export`, then `anonymize`, then `verify`; it stops after `export` only
for codes other than 0 and 2. If some chats failed during export but anonymize and
verify passed, `run` still exits with 2.

The usual first run is `login`, then `chats` (check the table, adjust `[chats]` and
`[staff]` if needed), then `run`. After that, run `run` periodically: only new messages
are fetched and virtual ids stay stable.

## Which chats are exported

By default groups and supergroups. Private dialogs, broadcast channels, bots and
Saved Messages are skipped. Chats whose members are all staff (`[staff]`) or bots are
considered internal and skipped too; when the member list is hidden the chat stays in
and the table says so (`included (member list participants hidden)`). Archived chats
are included by default. Chats the account has left or has no access to are skipped.

A legacy group that was upgraded to a supergroup is merged with it into one logical
chat, even when the old group has already disappeared from the dialog list (the tool
discovers it from the supergroup's info). Every rule is configurable in `[chats]`:

```toml
[chats]
include_types = ["group", "supergroup"]   # add "private" to include 1:1 dialogs
include_ids = []                          # if non-empty, ONLY these chat ids
exclude_ids = []                          # chat ids to skip
exclude_title_regex = []                  # e.g. ["^\\[INT\\]", "internal"]
include_archived = true
exclude_internal = true                   # skip chats whose members are all staff/bots
```

The dialog list is requested once per run.

## Anonymization

Text is processed in this order:

1. Telegram's own entities (exact offsets): `@user` mentions become `@U#####` (`@C#####`
   for an exported public chat), e-mail, phone, card and link entities become
   placeholders. Full-width punctuation is folded before that; right after it the
   text is normalised so nothing hides behind invisible characters: soft hyphens,
   zero-width, bidi and other format characters are dropped, a zero-width joiner or
   variation selector only between two letters or digits (emoji sequences stay),
   Russian stress marks are dropped, and the text is composed to NFC (a decomposed
   `ё` or `й` in a macOS file name equals the name it spells). The leak scanner and
   every name and keep term use the same normalisation.
2. IBANs (with the mod-97 checksum, in any case and grouping, and at each country's
   own length, so a currency code behind the account cannot swallow it:
   `KZ86125KZT5004100100 KZT`), then bank cards. The
   text is cut into groups of card characters (digits and the characters people use
   to mask a card by hand), and only windows shaped like a card count: one contiguous
   13-19 digit run, 4-4-4-4 with an optional shorter tail, the 4-6-5 of American
   Express and, for your own BINs only, missing spaces or an extra digit. A window is a
   card when it starts with a configured BIN (typos, hand masks and a single line
   break included) or, for all-digit windows, when it passes Luhn. Two phone numbers
   on adjacent lines, a list of BINs, dates and columns of amounts therefore never
   become cards. A file name separates its fields with `_`, so a card glued to a word
   with one is masked too, and then it must carry a configured BIN or a full 16-digit
   network number - otherwise every Luhn-valid timestamp in a file name would become a
   card. An expiry date and CVV typed after the number, on the same line or
   the next one, as fields of a dump (`|12|27|123`), or - anywhere in a message that
   carries a card - after `код` or a bare `до`, are masked with it.
3. The shared rule table. Pasted Telegram Desktop headers (`Пётр Иванов, [12.03.2024
   10:15]`, their indentation kept) and `[Forwarded from ...]` lines come first, so
   that a name part that also holds a handle, an address, a link or a card is still
   read as one header and becomes one `<name>`. Then proxy strings and links (also
   scheme-less `host/path`), so a credential disguised as a link, or an explorer URL,
   is one placeholder; then unambiguous tokens (bot tokens, JWTs); then XML and SOAP
   elements, where the tag names the kind of value (`<Password>`, `<CVV2>`,
   `<ApiKey>`, `<Login>`) and a keyword rule would otherwise read the markup around
   the value as its own label; then the domain rules
   (`fintech.py`): financial and identity data that clients commonly paste into
   support chats (card companions, credentials and secrets in every common shape,
   seed phrases, crypto, CIS identity documents, addresses, people named next to a
   keyword, bank details, ad-platform and messenger ids, payment references). Almost
   all domain rules are keyword-gated (`cvv 123`, `password: ...`): only the value is
   replaced, the keyword and everything between stay visible, so the model still sees
   what was discussed and a name or e-mail inside the label is still scrubbed by the
   later layers. The value may also stand on the next line after the label.
4. Generic regexes for what Telegram did not annotate: e-mail (also mistyped or
   obfuscated), `@handles` (also glued to words, spaced, inflected),
   name + patronymic pairs, also in capitals as payment details print them
   (`ПЕТРОВ ИВАН СЕРГЕЕВИЧ`) and, after a person keyword, in lower case
   (`фио: смирнов алексей викторович`, `меня зовут иван смирнов`),
   tokens and secrets (long hex and base64 strings; a long run made only of words,
   numbers, versions and dates is an identifier and stays, unless it hides a number of
   five or more digits or a split phone, card or document number, is a grouped
   licence key, names a secret or stands where a login goes; the leak scanner applies
   the same test), IPv4/IPv6 (loopback and the unspecified address stay — `127.0.0.1`,
   `0.0.0.0`, `::1`; a dotted quad right after a
   version or clause word is a version, and so is a version-shaped one after an update
   verb, an app name or a product that numbers its releases in four parts (`SDK`,
   `БП`, `1С`) — unless a network word such as `IP` or `сервер` comes before, the quad
   carries a port, or the number is one no release is numbered by),
   INN/OGRN/SNILS (with checksums), bank account numbers, phones in every spelling
   (national CIS formats, `+cc` international forms, digit by digit, typographic
   dashes and dashes with spaces around them, glued to `тел.`, bare numbers after a
   phone keyword; the Russian national shape is matched wherever it starts, so a
   number in front of it cannot hide it, and only the number itself is replaced, so
   a time or an amount the shape ran into stays; a generic run never starts on an
   amount or a date unless a phone word labels it, and amounts side by side are not
   a phone), the participants' own profile numbers in any grouping (the layer the
   self-check hunts with), messenger handles after a keyword; then bare
   domains become `<domain>` (`scrub_domains`, `allow_domains`), known usernames become
   their virtual id, `custom_patterns` become `<redacted>`, and `keep_terms` are
   protected. Domains, usernames and custom patterns go before keep terms because a
   keep term is a word, not a licence for a host, a username or an operator's own
   regex that contains it (`northwind_ivan` is
   still a username, `Northwind-104233` is still the pattern's match; a username that
   *is* the keep term stays bare): only a
   host that is the keep term itself, the keep term plus a suffix (`northwind.ru`) or
   part of a longer keep term (`ASP.NET Core`) stays. A suffix that is an English word
   or a payment product (`money`, `pay`, `store`, `app`, `it`, `in`, ...) makes a host
   only in lower case or in a fully upper-case host, so `Yandex.Money` stays while
   `acme.store` and `Ромашка.РФ` go.
   A link that the policy keeps (`url_mode = "keep"`, `allow_domains`) goes through
   the same layers after its host, and user info before the host becomes
   `<credentials>`: cards, wallets and transaction hashes are masked anywhere in it,
   query values and the fragment get the whole rule
   table (`?password=<password>`, `?inn=<inn>`, `?to=<domain>`; a nested link follows
   the link policy), the path only the classes that need no keyword (links, tokens,
   e-mails, credentials), so routes and ids stay; bare hosts, custom patterns, keep
   terms and the vocabulary (`/clients/<org>/`) follow. Percent-encoded values are
   read as the text they spell before the layers run
   (`?q=%D0%9F%D0%B5%D1%82%D1%80%D0%BE%D0%B2` is a surname, `?phone=8%20916%20123%2045%2067`
   a number), and a value that holds nothing identifying keeps its encoding as it
   arrived; escapes that spell the link's own structure (`%2F`, `%26`) stay escaped.
   Under `url_mode = "domain"` a host that reads as a client or a person of the
   roster (`romashka.ru`, `ivan-petrov.github.io`) becomes `<url>`, not
   `<url:host>` — the organisation list exists to hide exactly that name.
5. Vocabulary: usernames of known participants and of the exported public supergroups
   and channels (rendered as that chat's `@C#####`), written bare, after `@` anywhere,
   or after a handle keyword — except a chat username that spells only product words
   (`payments`, `webhooks`, `sandbox_api`), which is replaced after `@`, in a `t.me`
   link and after a handle keyword but kept as a bare word, so the API term stays in
   the corpus (a person's username is replaced bare whatever it spells); numeric ids
   of known participants, of the chats that were exported and of the chats and people
   the export only names in passing (a linked channel that posts, the source of a
   forward), plus any marked supergroup or channel id (`-100` and ten to thirteen
   digits) whoever it belongs to, all as `<id>`; last names and full names of every
   known participant (also when the whole name was typed into the first-name field),
   and the contact names read from the catalogued private dialogs that were not
   exported (`Мария Кузнецова`), removed as whole phrases only; significant words from
   chat titles, including the old title of a merged legacy group (two-character words
   only when they mix a letter and a digit, such as `Z9`); `custom_terms` (as `<org>`).
   Cyrillic and Latin case folding, ё/е folding, transliteration, a closed class of
   Russian and Latin case endings (fleeting vowels included), every case form of an
   adjectival surname (`Ковальский`, `Ковальского`, `Белый`, `Белой`, `Белую`), the
   nominative of names ending in `й`, `ь` or a Latin `-o` (`Андрей`, `Коваль`,
   `Shevchenko`), both halves of a hyphenated surname (`Смирновой-Кузнецовой`), `_` and
   a following number as word boundaries (`petrov1990`, `IMG_Petrov2.jpg`; a term that
   ends in a digit still needs the whole token, so `S3` is not inside `S30`).
   `ALL_CAPS_CONSTANTS` keep organisation terms (`ERR_ROMASHKA_TIMEOUT`), while a file
   name (`PETROV_PASSPORT.pdf`) and a person's name in one (`WALKER_TIMEOUT`,
   `SEVEROV_PASSPORT_SCAN_2026_03_12`) are still scrubbed.
   A participant's full name or a `custom_terms`
   phrase is removed as a whole even when one of its words is in `keep_terms`
   (`Анна Мороз` with `мороз` kept, `Northwind Kazakhstan` with `Northwind` kept); a
   `keep_terms` phrase is kept only as the whole phrase, so a surname inside it
   (`Кузнецов` in the kept `Кузнецов Pay`) is still removed everywhere else and
   `verify` does not report it inside the phrase.

Ticket and order numbers, error and decline codes (`decline 05`, reason codes),
version numbers, dates, amounts and currencies, merchant descriptors, card statuses
and country names are left alone: that is the raw material for a glossary. The one
exception is a bare 13-19 digit number that passes Luhn, which is masked as a card
(see [Known residuals](docs/RESIDUALS.md)). The last
four digits of a card mentioned on their own (`card *1234`) also stay: that is how
the parties usually refer to a card, and PCI DSS allows it. The keyword rules
therefore work like this:

* a short keyword is a whole word: `пинг`, `pinned`, `другая`, `вуз`, `индексация`,
  `сроки`, `export`, `cidr` are no PIN, birthday, licence, postcode or expiry labels,
  while case forms (`пинкода`, `сроком`, `срока действия`, `индексом`), glued values
  (`PIN1234`, `cvv123`) and glued words of the other script (`pinкод`) still are;
* after `срок` (or `exp`) only a card expiry is replaced (`срок 12/27`, `срок действия
  карты 12/27`, `exp 1227`): a full date (`срок до 12.03.2026`), a day and month (`срок
  оплаты 10.02`, a two-digit year below 13) and a duration (`срок 10-14 дней`, `срок
  ответа 12 24 часа`) stay;
* after `cvv`, `pin` or an expiry word, a number right after an error word
  (`cvv mismatch, error 4001`, `пин ошибка E1234`) or, after a clause break, after an
  order, amount or id label (`cvv верный, заказ 4821`) stays; an error word before
  the keyword proves nothing (`Ошибка! Пин 1234` is still a PIN);
* a bare `код`/`code` is a one-time code (`код 482913`), except for a reference:
  a code kind right after it (`код ответа 4001`, `код категории 5411`, `код
  терминала`, `код магазина`, `код валюты`), a kind word or a decline before it
  (`ответный код 4001`, `promo code 12345`, `отклонена с кодом 4001`, `отказ по коду
  4001`), and, for a number of up to five digits, an explanation after it (`код 4001
  означает ...`, `коды 4001 и 4002 означают отказ`, `код 5003 = таймаут`, `код 6001
  это отказ`) or a numeric JSON field (`"code": 4001`). `код подтверждения`, `смс
  код`, `3ds код` and `otp` always introduce a one-time code;
* after a password label, an outcome or state word (`неверный`, `неверен`,
  `сброшен`, `истёк`, `устарел`, `подходит`, `expired`, `3ds-check`, `null`, `false`)
  is prose, unless
  it carries a digit or a symbol (`Верный1`); a state word before a value that has a
  digit or a symbol belongs to the label (`пароль: новый Qwerty123`);
* a password label also stays prose when it states a policy (`пароль 8-64 символа`,
  `пароль: минимум 8 символов`) or an instruction that the sentence goes on to finish
  without naming a value (`пароль: придёт отдельным письмом`, `пароль: только
  латиница`); a lone instruction word is the value (`пароль: придёт`), and so is a
  password behind one (`пароль: только Qwerty123`).

Rules without a keyword follow the same idea:

* a bare 10-, 12-, 13- or 15-digit number that passes an INN, OGRN, IIN/BIN or RNOKPP
  checksum is a tax id (one random number in eleven passes such a check), except right
  after an order, ticket, transaction, invoice or payment label: `заказ`, `тикет`,
  `транзакция`, `инвойс`, `обращение`, `заявка` in every case form, `order`, `ticket`,
  `transaction`, `txn`, `invoice`, `номер платежа`, `ID операции`, `id оплаты`,
  `payment id`, with only punctuation, `№`/`#`, `id`, `номер` or one line break in
  between (`заказ №3184713454`, `Номер заказа:\n7700000425`, `order_id=7700000425`).
  A plural label carries the whole list it introduces, so every number of it is a
  reference and not only the first (`заказы: 3184713454, 7700000425, 7700000016`); the
  list ends at anything but a number closed by `,`, `;` or `/`, so `заказы: 12345, ИНН
  7700000425` is a tax id again. `заказчик` (the customer) and a bare `платёж`,
  `оплата`, `перевод`, `операция`, `чек` or `id` are no such labels (`ИНН заказчика:
  ...`, `реквизиты для оплаты: ...`, `national ID: ...` are still scrubbed), and a
  tax-id, requisites or counterparty word shortly before the label keeps the number a
  tax id (`ИНН по заказу: <inn>`);
* after a coin or wallet keyword (`usdt`, `btc`, `ton`, `кошелёк`) a dash or an
  underscore ends an address, so an order reference or a constant stays
  (`usdt: INV-20260312-000123-ABCD`, `USDT_TRC20_WITHDRAWAL_DISABLED`) and an address
  with a suffix loses only the address (`sol <wallet>-mainnet`); an address or a hash
  that keeps its own shape is removed even with a label glued in front of it by an
  underscore (`usdt_<wallet>`, `кошелек_<wallet>`), so an identifier that happens to be
  address-shaped goes with it (`ORDER_<wallet>`); a value that starts
  like a TON address keeps its dashes and underscores, so a TON address glued to a
  word or cut short is still removed whole;
* a user-agent (`Mozilla/5.0 (...)`) ends with its last product token, comment,
  in-app bracket or in-app suffix (`Instagram 310.0.0.34.111 Android (...)`), so an
  error code, status, log field or sentence after it stays (`UA <user-agent> —
  ошибка 4001`, `"<user-agent>" rt=0.5 err=4001`); a clock with a year in front or
  milliseconds behind (`[12/Mar/2026:10:00:00 +0300]`, `10:00:00:123`) is no IPv6
  address.

Every significant chat-title word counts as a client organisation name, so your own
product or company name, which usually sits in every chat title, is scrubbed as
`<org>` too until you add it to `keep_terms`. Generic words are not: the generic
halves of company names and the core payments and support vocabulary (`Групп`,
`Банк`, `Технологии`, `Сервис`, `Pay`, `Card`, `Wallet`, `Store` and the like, Russian
ones in every case form) never become organisation terms, so `в группе`, `банк
отклонил` or `Apple Pay` survive in the text; a surname-shaped form (`Банков`,
`Туров`) still counts as a name. Neither do the feature words a title often carries
next to the client (`Ромашка — вебхуки`, `Василёк / Касса`, `Лотос [прод]`):
`подключение`, `касса`, `вебхуки`, `возвраты`, `подписки`, `песочница`, `миграция`,
`сверка`, `отчёты`, `чеки`, `фискализация`, `ККТ`, `ОФД`, `СБП`, `3DS`, `прод`,
`личный кабинет`, `оплата`, `сделка`, `сплит`, `checkout`, `webhooks`, `refunds`,
`sandbox`, `subscriptions`, `widget`, `P2P`, `B2B`, `POS`, `NFC` and the like stay in
the corpus — they are exactly the product knowledge the dataset is built for. A client
actually named after one of them needs `custom_terms`. Nothing is whitelisted by a guess: in a
small export a client with a few chats (`Ромашка support`, `Ромашка sales`,
`Ромашка integration`) is as frequent as the product name. A title word present in at
least `generic_title_share` (20 %) of chat titles and in at least three of them is
only *suggested* for `keep_terms`: `anonymize` prints it and the private scrub report
lists it under `keep_terms_suggested`. A word the anonymizer removes as a
participant's name (an account manager's surname in every client chat title, in any
case form or Latin spelling), or one already in `keep_terms` or `custom_terms`, is
never suggested. A name your policy keeps in text anyway — first names under
`name_mode = "first"`, surnames with `scrub_last_names = false` — can be suggested;
accepting it keeps the word only where the policy already kept it, and the full
`First Last` phrase still goes. `custom_terms` always win over the title heuristic,
and nothing derived from chat titles is written into the shareable dataset.

A Telegram display name is free text (a company name, `First Last`, a phone number),
so it is scrubbed as well: only the first word is kept, and only when nothing in it
had to be removed and no word of it is a known username (`Kotik` for `@kotik`, in every
`name_mode`); otherwise the name is empty. Deleted accounts are shown as
`Deleted`. A last-name field that is a role or team label (`Support`, `Поддержка`,
`Служба поддержки`, `Staff`, `Client`, `Team`) is not a surname: the word is not
removed from messages and `verify` does not report the dataset's own role labels.

A kept name never shows somebody else's name, and never a surname on its own. Under
`name_mode = "first"` a first-name field that holds nothing but a surname (`Кузнецов`,
`Смирнова`, `Кузнецов А.`) becomes an empty name, and so does one that spells a
participant's surname in any spelling the scrubber hunts for (`Петрова`, `Petrov` next
to `Иван Петров`); a given name that merely inflects onto a surname is kept (`Марина`
next to the surname `Марин`). A bot named after a person (`Олег Северов`,
`Petrov Assistant`) loses its name in every mode. Under `scrub_last_names` such a lone
surname is removed from message text as well.

Policy options in `[anonymize]`:

| Option | Default | Effect |
|---|---|---|
| `name_mode` | `"first"` | `first`, `full` or `none`: what display name virtual users keep. Under `none` first names are also scrubbed from text, except first names that are ordinary words (`Тема`, `Max`); those are listed after the run and in the private scrub report, never in the dataset. |
| `keep_chat_titles` | `false` | Titles usually name the client organisation, so they are replaced by `C#####`. A chat's public username is hidden either way. |
| `keep_service_messages` | `false` | Join/leave/pin/title-change events. |
| `keep_bot_messages` | `true` | Set `false` if bots only add monitoring noise. |
| `keep_file_names` | `false` | Attachment names (scrubbed like text) next to `[document:pdf]`. The extension is shown either way, but only when it is one: a name ending in something else keeps the extension of its MIME type, or none. |
| `url_mode` | `"drop"` | `drop`, `domain` or `keep` (`keep` can expose client hosts; `domain` hides a host that reads as a client or a person of the roster). A link that cannot be parsed (`http://[your-domain]/admin`) is always `<url>`. |
| `allow_domains` | `[]` | Exact hosts kept verbatim, in links and in bare text (a subdomain of an exact entry is not kept); `*.example.com` keeps the host but hides the subdomain (`<sub>.example.com`), so client tenants do not leak. Secrets, redirect targets and client names inside a kept link are still removed. Telegram links are always hidden. List your own hosts here: `keep_terms` keep a host only when it is the keep term itself or the keep term plus a suffix. |
| `keep_terms` | `[]` | Product and company names that are never scrubbed on their own. Put your product name here: chat-title words are scrubbed otherwise. Matched case-insensitively, with ё/е folding and with invisible characters and stray blanks removed, so a term pasted out of a chat still matches; a bare public-chat or person handle that a keep term spells whole is kept too, while its `@` form and `t.me` link are always replaced. A participant's full name or a `custom_terms` phrase that contains a keep term is still removed as a whole. |
| `custom_terms` | `[]` | Extra organisation names replaced with `<org>` (two characters or more, whole word, case-insensitive, also transliterated, but not inflected: a two-character term also removes the ordinary word it spells (`яр` for `ЯР`), and its case forms (`Яру`) need their own entries). |
| `custom_patterns` | `[]` | Extra regexes replaced with `<redacted>`: case-insensitive and multiline, and the whole match is replaced, so match only the value (`(?<=КПП\s)\d{9}`) to keep the keyword. A pattern wins over a `keep_terms` word inside its own match, and the leak scanner reports the same matches. A pattern that can match the empty string is rejected at load time. |
| `card_bins` | `[]` | BINs (first 6 digits) of your product's cards; card numbers become `424242**********` and are recognised by BIN even with typos. |
| `scrub_domains` | `true` | Bare domains in text become `<domain>`; `allow_domains` are kept (a wildcard entry as `<sub>.example.com`). The private report lists the most frequent ones, so public hosts can go into `allow_domains`. |
| `scrub_last_names` | `true` | Remove last names of known participants from message text. |
| `scrub_chat_titles` | `true` | Remove chat-title words (client org names) from message text. |
| `generic_title_share` | `0.2` | Share of chats (and at least three) a title word must appear in to be suggested for `keep_terms`. It is scrubbed either way. |

Checks:

* `anonymize` aborts (exit 3) when a real id, `@username` or phone number (in any
  national spelling) survived in the output. This self-check is high-precision: a hit
  is a bug, not a false positive.
* `verify` additionally hunts for last names and full names, chat titles, bare
  domains, custom patterns and every regex class above, over the written dataset
  files. It needs the raw export: every id, username, phone and name it hunts for
  comes from `data/raw/`, so `verify` refuses to run (exit 1) when the export is
  gone, rather than certifying the dataset after finding nothing. Delete the raw
  export after the audit, not before.
  Every file under the dataset directory is read, whoever wrote it, and every hit
  names the file, row and field. JSON files are scanned as decoded strings, keys
  as well as values (so a line break inside a message is seen the way the scrubber
  saw it); anything else is scanned line by line. The dataset's own `README.md` is
  the one file skipped, and only while it is unchanged: it names every placeholder.
  People's names and chat-title words are hunted where the dataset carries free
  text: message text, attachment names and extensions, and chat titles in the JSON
  files (title words also in the kept display names of `users.json`). The fields the
  writer fills itself (roles, sides, dates, policy values) and the transcripts and
  chunks, which only repeat those JSON fields around fixed English labels, are
  scanned for ids, usernames, phone numbers, domains, custom patterns and the regex
  classes. So a surname or title word that equals or transliterates onto a label
  (`Бот`, `Форум`, `Формат` next to `BOT`, `Forum chat`, `Line format`, or a city
  in the time zone name) does not fail a clean dataset, and nothing needs to go into
  `keep_terms` for it. A transcript line is scanned in the parts the writer composed
  it from — head, quoted snippet, body — so its own layout never glues a keyword to
  the next part's value (`подскажите пароль": Добрый день`, `Nick: Hello`), while a
  chat header pasted into a message is still recognised in the body.
  A JSON file or row that does not parse, and any file the
  writer does not produce, is scanned in full. The only exceptions `verify` makes
  are the scrubber's: your `keep_terms` and the hosts that `allow_domains` and
  `url_mode` keep. A short surname inside a kept first name
  (`Ким` next to `Аким`) is hunted, and so is a person named next to a keyword
  (`менеджер Анна Смирнова`) even when `Анна` is a kept display name.
  `verify` is deliberately fuzzy and may produce false positives: read
  `data/anon/verify_report.json` and tune `keep_terms`, `custom_terms` or
  `custom_patterns`, then re-run `anonymize` and `verify`. The scanner and the
  scrubber share one rule table and one text normalisation, so the two cannot
  disagree about a class of data; a name, title word or `custom_patterns` match that
  spells one of the scrubber's own renderings never flags it — a placeholder
  (`Token`, `Wallet`), the handle it writes (`@user`, `@U04217`) or a masked card's
  visible BIN — while a typed autolink is
  not a placeholder and is read for what it holds (`<mailto:…>`, `<tel:…>`).
* `data/anon/anonymize_report.json` (private, mode 600) shows how many replacements
  each rule made, with samples, and the most frequent surfaces of the name and
  organisation rules, so a common word that fires hundreds of times as a "name" is
  easy to spot and put into `keep_terms`. It also lists the most frequent link
  domains and the most frequent scrubbed bare domains (`top_surfaces.domain`; a
  public host such as `aliexpress.com` that fires often belongs in `allow_domains`),
  the `[staff]` entries that matched nobody, the chat-title terms that were
  scrubbed, the public chat usernames that were removed as a bare word as well
  (`chat_usernames_scrubbed_bare`, with their counts in `top_surfaces.bare_username`),
  the frequent title words suggested for `keep_terms`, the first names kept
  in text because they are ordinary words, and the third-party names that entered the
  vocabulary from forward headers. Nothing name-derived goes into the shareable
  `manifest.json`.

What the anonymizer is known to get wrong - the leaks that can survive, the product
knowledge that can be removed by mistake, and the limits of `verify` - is listed with
its workaround in [docs/RESIDUALS.md](docs/RESIDUALS.md).

Both commands cost time proportional to the text they read, whatever the text
contains. A message that is mostly blank lines, spaces or tabs after a street
keyword, a seed word or `С уважением` costs no more than an ordinary one: those
rules take a run of blanks as a whole instead of trying every way to split it. The
vocabulary costs the same per character with ten participants as with several
thousand: the terms are grouped by the character they start with, and only the group
of the character actually in front of the pattern is tried.

After `anonymize` the tool prints users who write in three or more client chats but
are not configured in `[staff]` (most likely colleagues who should be added to the
config), the words found in the titles of many chats (scrubbed as `<org>`; if one of
them is your product or company name, add it to `keep_terms` and re-run, never add a
client's name), the chat-title words it scrubbed as `<org>` (add product words to
`keep_terms`), the public chat usernames it also removed as a bare word (add one to
`keep_terms` if it is a product or API term; its `@` mentions and `t.me` links are
replaced either way), and under `name_mode = "none"` the first names it kept because they
are ordinary words (printed for you and listed in the private scrub report, never in
the dataset's `manifest.json`).

## Account safety

The key requirement: the support account must not end up banned. Below is what is
known about this from Telegram's documentation, Telethon's documentation and source,
and community reports, and how the tool takes it into account.

**What actually gets accounts banned or limited.** Every documented case involves
either the origin of the account or "writing" actions: fresh accounts and virtual
(VoIP) numbers (often banned minutes after the first login through Telethon),
purchased accounts behind proxies, mass mailings, forwards, invites, adding people to
groups, contact imports, joining many groups, mass username resolution. Telegram's
official spam FAQ lists only complaints about unwanted messages and adding people to
groups. The "limited" statuses (`PEER_FLOOD`, `USER_RESTRICTED`, a frozen account,
`USER_DEACTIVATED_BAN`) are anti-spam statuses; they are not issued for reading. A
separate class of incidents is not a ban but a "logged out on all devices" event: it
has been caused by odd device or OS strings in the client fingerprint and by using
one session file from two IP addresses at once (`AUTH_KEY_DUPLICATED`, after which
the session is invalidated for good).

**What all sources agree is safe.** Reading the history of chats the account is
already a member of, from a long-lived account, from one session on one IP address,
at a moderate pace. Telethon's documentation says that legitimate use cases get
neither flood waits nor bans; telegram-export, mautrix-telegram, tg-archive and
corporate write-ups reach the same conclusion. Telegram does warn that accounts
logging in through unofficial clients are automatically placed under observation, and
it publishes no exact read limits: the only signal is `FLOOD_WAIT_X`, which simply has
to be waited out in full.

**How the tool behaves.**

* Read-only. No sending, no joining, no username resolution (`[staff]` entries are
  matched locally against users already seen), no contact import, no read receipts,
  no media download. The dialog list is requested once per run.
* Pacing. History pages are spaced `wait_time` apart (1 s) by Telethon itself, with no
  random addition: one page request per second, up to about 30 in 30 s. Telethon's
  documentation estimates the safe rate for history requests at about 10 per 30 s, so
  raise `wait_time` to 3 for that pace, or higher if flood waits appear. The tool's own
  pauses -- before each next chat (`chat_wait`, 3 s) and between chat-info and
  member-list requests (`participants_wait`, 2 s; Telethon itself does not sleep between
  member pages) -- each get a random addition of up to half their length. Chats are
  processed strictly one after another over a single connection. Order of magnitude:
  1 million messages is about 10,000 requests, about 3-4 hours at `wait_time = 1`;
  hundreds of chats fit into days, which is the intent.
* `FloodWait` is waited out in full plus a random few seconds (Telethon sleeps
  through waits up to `flood_sleep_threshold`, 1 hour, on its own and the console
  shows `INFO telethon.client.users: Sleeping for Ns ...`; the tool handles the rest). A wait longer than `max_flood_wait` (2 hours) means the account is being
  asked to slow down seriously: the run stops with the cursor saved and can continue
  the next day. Switching to another chat would not help: Telethon remembers flood
  waits per request type.
* Fatal states (`PEER_FLOOD`, `USER_RESTRICTED`, a frozen account,
  `USER_DEACTIVATED_BAN`, `AUTH_KEY_DUPLICATED`, a revoked session) stop the whole
  run with exit code 2 and a hint to check @SpamBot, rather than skipping the chat
  and moving on. The script never logs in again by itself: `login` is manual, in the
  terminal.
* One process per session: a lock file next to the `.session` file. A second run
  gets `another tg-collector process is using the session`. Do not copy the
  `.session` file between machines and do not run the export on a laptop and a
  server at the same time.
* A constant, honest client fingerprint: `device_model = tg-collector`, a plain OS
  version string, the application version. The update stream is off
  (`receive_updates=False`, except during `login`, where the QR flow needs it), so
  the client does not pull updates from hundreds of groups for hours.
* Optional takeout mode (`[export] takeout = true`): history is read through
  Telegram's official data-export session (what "Export Telegram data" in Telegram
  Desktop uses). It has relaxed limits on reading history, but before the first run
  Telegram notifies all devices and asks you to confirm the export in the official
  app or wait up to 24 hours (`STOPPED: Telegram requires confirmation of the data
  export ...`). Recommended for the first full export; the export session id is
  stored, so later runs need no confirmation. Dialog and member requests still go
  through the normal session.
* Your own `api_id`/`api_hash` from my.telegram.org for this account's phone number,
  not somebody else's and not from examples. A real, long-lived number, without
  proxies or VPNs that change the country.

**What the Telegram API terms forbid, and what to keep in mind.** Clause 1.5 of the
API terms of service (core.telegram.org/api/terms) prohibits using data obtained
through the API to train or fine-tune AI models. An anonymized export for support
analytics, with a model used as a tool to write a knowledge base and no training on
the data, is a different situation, but the wording is broad: if you plan to fine-tune
on the data, decide that separately. Exporting your own data is explicitly recognised
as a user's right (privacy policy, section 9.1). None of this is legal advice.

## Data and security

```
data/
  session/support.session      Telegram authorization key: treat like a password
  session/support.lock         single-process lock (harmless)
  raw/                         raw export with every real identifier: never share
    chats.json, users.json, state.json, messages/<chat>.jsonl
  anon/mapping.json            U#####/C##### -> Telegram ids (secret)
  anon/anonymize_report.json   replacement counts with raw samples (private)
  anon/verify_report.json      leak matches with raw tokens (private)
  anon/dataset/                anonymized dataset: the only part you can share
```

Everything the tool writes is readable by your user only: files are created with mode
600 and directories with mode 700 (the tool sets its umask to `077`), and the JSON
files (raw store, mapping, both reports) are written atomically through a temporary
file that has mode 600 from the first byte. At every start the folders the tool owns
(`raw/`, `anon/`, `session/`) and the session files themselves lose group and other
permissions, wherever `TG_SESSION` points, so an export or a session key written by an
older version with mode 644 is out of reach of other local users too. Nothing else is
touched: the directory `TG_DATA_DIR` names keeps its own mode, because it may be your
home or project directory. `.env` holds `api_hash` and your phone number and is never
written by the tool, so run `chmod 600 .env` once yourself. The dataset is private on
disk as well; share it by copying it. `verify` never moves a dataset that fails the
check: the matches are often false positives, so you judge them and re-run.

`.env`, `config.toml`, `*.session` and `data/` are in `.gitignore`.

Limitations: edits and deletions made after a message was exported are not tracked
(use `export --full`); attachments are not downloaded, only their type and size stay
in the text (`[photo]`, `[document:pdf 1.2 MB]`, `[voice 0:41]`); forum topic titles
are not exported (only topic ids); hidden member lists are filled in from message
senders.

Known residuals of the anonymizer - what it is known to get wrong - are listed in
[docs/RESIDUALS.md](docs/RESIDUALS.md), grouped into leaks (identifying data that can
survive), over-scrubs (product knowledge that can be removed by mistake) and the limits
of `verify`, each with the workaround. Use `custom_patterns` and `custom_terms` for
anything specific to your data, and read the private report after every run.

## Development

```bash
uv run pytest -q
```

`tests/conftest.py` holds what the rule tests share: `check`, the two-direction
assertion every rule is tested with (the text scrubs to exactly what is expected, the
leak scanner is silent on that output, and it flags the raw text exactly when
something was removed); `assert_fast`, a deliberately generous timing budget that
catches catastrophic backtracking rather than the load on the machine running the
suite; `assert_cost_ratio`, which times a small and a large input back to back so that
a busy machine can only understate the ratio; and the secret-shaped fixtures, joined at
import time from obviously invented parts so no line of this repository reads to a
credential scanner as a leaked key.

`tests/test_public_hygiene.py` holds the repository to the same standard it applies to
a chat: it reads the published tree and fails on a value shaped like a live provider
key, a real person, company or identifier, a payment-network test card outside the
documented BINs (`424242`, `400000`, `510510`, `520082`, `601111`, `353011`), an
invisible character written as itself instead of as an escape, or a comment that cites
a review item or tells the story of a change instead of stating a rule.

Modules in `src/tg_collector/`:

* `cli`: commands, flags, exit codes; wires the modules together.
* `config`: `.env` and `config.toml` parsing, defaults, validation.
* `model`: plain record types of the raw export, roles and sides.
* `errors`: conditions that halt a whole run (the `STOPPED:` messages).
* `telegram`: the only module that talks to Telethon: session and lock, login,
  dialogs, member lists, paced history reads, flood-wait handling, takeout.
* `rawstore`: append-only raw store with a per-chat resume cursor.
* `export`: chat selection (`plan`) and incremental export.
* `cards`: finding card numbers in free text and masking them to the BIN.
* `rules`: the shape of a scrubbing rule and the keyword-gated rule builder.
* `fintech`: domain rules for financial and identity data.
* `bip39`: the BIP39 word list and a trie-shaped regex for seed phrases.
* `scrub`: text scrubber and leak scanner sharing one pattern table.
* `anonymize`: virtual-id mapping, vocabulary, transformation, fail-fast self-check.
* `dataset`: episodes, transcripts, chunks, manifest, the dataset README.
* `verify`: leak audit of the written dataset.

## Publishing and privacy checklist

* `config.toml`, `.env`, `*.session` and `data/` are gitignored; keep them that way.
* Never commit or share `data/anon/mapping.json` or anything under `data/raw/`.
* `data/anon/anonymize_report.json`, `verify_report.json` and `anonymize_abort.json`
  contain raw tokens; read them, do not share them.
* The console output quotes raw data too: `login` and `chats` print names, usernames
  and dialog titles, `export` reports a failed chat by its Telegram id, `anonymize`
  lists chat-title words and kept first names, and `verify` prints the matches it
  found. Redact it before pasting it into an issue, a chat or a screenshot. The
  `ABORTED:` line itself is safe — it names kinds and virtual locations only.
* Before handing out `data/anon/dataset/`, review `anonymize_report.json` for
  over-scrubbing and make sure `verify` exits with 0 (or that every remaining hit is
  a confirmed false positive).
* `api_hash` is a password-level secret; do not paste it into issues or screenshots.
* Run `uv run pytest -q` before pushing: the public-hygiene tests are what keep a
  fixture from reading to a credential scanner, or to GitHub push protection, as a
  leaked key of a real account.
