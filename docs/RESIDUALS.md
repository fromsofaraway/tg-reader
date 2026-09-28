# Known residuals

What the anonymizer is known to get wrong. Every item belongs to exactly one
of three sections, and the worst comes first:

* [Leaks](#leaks) - identifying data that can survive into the dataset.
* [Over-scrubs](#over-scrubs) - product knowledge that can be removed by
  mistake.
* [Verify limits](#verify-limits) - what `verify` does not hunt, and what it
  reports on a dataset that is in fact clean.

Each item names the workaround where one exists: `custom_terms` and
`custom_patterns` remove more, `keep_terms` and `allow_domains` remove less.
Read `data/anon/anonymize_report.json` after every run; it shows which rule
fired how often and on what.

The rules these items qualify are described in
[Anonymization](../README.md#anonymization).

## Leaks

### Names and organisations

* A person mentioned in free text is removed only when they are a
  participant, a forward author, or named next to a keyword or patronymic: a
  bare unknown "Иван Петров" stays. Workaround: `custom_terms`.
* A lower-case name is read only after a person keyword and only with a
  patronymic (`фио: смирнов алексей викторович`) or, after a
  self-introduction, a surname ending (`меня зовут иван смирнов`), so `фио:
  смирнов алексей`, `смирнов а.в.` and a bare `петров иван сергеевич` stay.
* A Latin surname does not catch its Cyrillic spelling; only the other
  direction is transliterated.
* Two-letter surnames are removed only together with a first name.
* A common word that is a first name stays under `name_mode = "first"`.
* A first name that is only the transliteration of the user's own username
  (`Максим` for `@maxim`) is kept.
* A role or team word in the last-name field or at the end of a
  forward-header name (`Support`, `Поддержка`, `Team`, `Staff`, `Sales`,
  `Dev`) is never a surname, so a real person with such a surname keeps it
  next to the first name (`Ravi Dev`), and a forward-header name made only of
  such words and whole keep terms (`Northwind Support`, or `Northwind Pay
  Support` with `Northwind Pay` kept) is not a name.
* A forward author's surname written on its own (`Громов сказал` after a
  forward from `Геннадий Громов`) is removed only under `scrub_last_names`
  and only when it is spelled like a surname and the header names a person,
  so `Иван Коваль` keeps `Коваль` and `Магазин Цветов` keeps `Цветов`.
  `verify` reports both for you to judge; `custom_terms` clears the report
  and renders the name as `<org>`.
* The title words of a chat the export does not contain (excluded, archived,
  or outside `--only`) are no organisation terms, so another client named in
  the text stays. Of the catalogued private dialogs, only a title of two or
  three capitalised words is read as a contact's name (`Мария Кузнецова`,
  never `Мама` or `Отдел продаж`), and only that whole phrase is removed.
  Workaround: `custom_terms`.
* A chat title made only of generic words (`Crypto Exchange Support`, `Банк
  Онлайн`, `Ромашка — вебхуки` beside the client's own name) yields no
  organisation term for those words, so a client actually called `Касса`,
  `Checkout` or `Сплит` needs `custom_terms`.
* A two-letter organisation name (`ЯР`) is not taken from chat titles; only
  two-character words that mix a letter and a digit, such as `Z9`, are.
  Workaround: `custom_terms` - see the caveat under [Over-scrubs](#names-and-organisations-1).
* A free-text first-name field such as `Ромашка Банк` still reads the second
  word as a surname.
* A line that *ends* in a bracketed date and time is read as a pasted
  Telegram Desktop header, so a log line in that exact shape loses its first
  field (`payment-service, [2024-03-12 10:15:00]` becomes `<name>, [...]`).
  A shouted log level is exempt (`ERROR, [2024-03-12 10:15:00]` keeps it), and
  a stamp with anything after it on the line is not a header at all.

### Handles and usernames

* A short plain username (fewer than eight characters, letters only:
  `kotik`) written without `@` and without a handle keyword stays, because
  such names collide with ordinary words.
* The public username of a chat that was not exported stays when written
  without `@`; after `@` it becomes `@user`, in a link `<tg-link>`. So does
  the username of an exported chat that spells only product words
  (`payments`). Workaround for both: `custom_terms`, if the chat is named
  after its client.

### Passwords and credentials

* A password after a multi-word label without a colon (`пароль от личного
  кабинета Qwerty123`) and a token after a multi-word label (`токен доступа к
  API: AbCd1234...`) are not recognised.
* When a password without a colon is followed by a label that is not a known
  field name (`пароль Qwerty123 от почты: Qwerty456`), the first password
  stays.
* A quoted passphrase that contains a word of an error message (`"мой пароль
  не менее 8 символов"`) is read as a message, so only its first word is
  removed, and only when that word has four or more characters.
* A token after the bare word `ключ` ("key") is removed only when it has a
  well-known prefix or a generic secret shape, because in integration chats
  `ключ` usually names a JSON field.
* A password after `-p` needs a digit plus mixed case or a symbol (`-p
  S3cretPass`), or, on a command that logs in (`mysql -u root -p secret99`),
  at least a digit, a symbol or mixed case; a password after a bare default
  account needs a letter plus a digit or a symbol. All-lowercase words (`-p
  secretpass`) and `admin:Password` therefore stay.
* `@` in a password is not recognised, neither bare (`admin:P@ssw0rd`) nor
  after a keyword (`доступ ivan:P@ssw0rd`), and neither is a pair glued to its
  flag (`-uadmin:pass`) or flags such as `-a pass` or `-U user%pass`.
* After `доступ`, `акк` or `учётка` the password half has to look like one, so
  an all-lowercase pair stays (`доступ: ivan:secretpass`).
* An XML element is read only when its tag ends in the secret word and its
  text is on one line, so `<PasswordHash>`, `<TokenValue>` and a value written
  across two lines keep their text.
* A password after a state word that has neither a digit nor a symbol
  (`пароль: новый Qwerty`) stays.
* A password that itself ends in a quote, bracket or sentence punctuation
  keeps that one character.
* A PEM private key pasted without its `END` line is scrubbed line by line and
  its short last line can stay; certificates and public keys are scrubbed line
  by line only.

### Codes, CVV, PIN and expiry

* A one-time code labelled with a code kind (`код магазина пришёл 482913`), or
  a short one followed by `означает`, stays.
* A real CVV, PIN or expiry right after an error word or, after a clause
  break, a number label (`cvv, ошибка 123`) stays.
* An expiry with a two-digit year below 13 (`exp 10/12`) or followed by a time
  unit (`срок 12.27 дней`) stays, and so does one after `срок действия` with
  more than a short word in between (`срок действия вашей карты 12/27`).
* After a bare `до` only `12/27` and `12-27` are read as an expiry, because
  `до 10.50` is an amount and `до 10 30` a time.

### Addresses and cardholders

* After an address keyword (`прописка`, `адрес регистрации`, `billing
  address`) text without a digit is removed only when it names a kind of place
  (`ул.`, `мкр`, `село`, `г.`), so a bare city or a city and street without a
  house number (`прописка: Алматы, Абая`) stays. Text with a digit that opens
  with a prose word (`не`, `можно`, `must`) is removed only when it shows a
  street, house or flat word or a part that ends in a house number, so
  `прописка: не помню, абая 150 угол ленина` stays.
* A lane after `пер.` is not recognised when a number, a lower-case
  preposition or a money word follows the abbreviation (`пер. на абая 10`).
  An English street name with a lower-case function word in it is read as a
  sentence.
* After `держатель карты` a name that contains a card product or bank word
  needs a surname ending or an initial (`держатель карты Anna Gold` stays),
  and a name after a product name that mixes a built-in product word with an
  unknown one stays (`держатель карты Acme Credit Олег Северов`).
* In a dump the cardholder name behind the CVV field stays
  (`...;123;IVAN PETROV`) unless a holder word introduces it.

### Documents and tax ids

* An upper-case `ID` or `no` and a 9-10 digit ticket number within 25
  characters after `паспорт` or `серия` are read as a document number
  (`паспорт не прошёл, тикет 1234567890`); a bare 7-digit number after
  `паспорт №` is not.
* A passport number written on the line below its series needs a number label:
  `Серия 4509` + `Номер 123456` goes, a bare `123456` on the next line stays,
  because there it is any number.
* An unlabelled number in a file name whose only signal is a checksum of
  another country (12-digit IIN/BIN, 13- and 15-digit OGRN, Ukrainian RNOKPP)
  stays, so that millisecond timestamps and build numbers do not become
  placeholders. Labelled and Russian-shaped ones go
  (`client_<phone>_report.xlsx`, `клиент_<inn>.pdf`, `иин_`, `снилс_`,
  `паспорт_`), and a number after an order, ticket or transaction word stays a
  reference across the `_` as well (`ticket_89991234567`,
  `ORDER_ID_7700000425`).
* A label behind a number counts only in brackets or after a dash (`заявка
  651214316007 (иин)`), because behind a comma or a space the same word
  introduces the next number instead (`заказ 7700000425, ИНН плательщика
  7701234567`). A single number labelled that way therefore stays a reference
  (`по заказу 651214316007 ИИН плательщика`).

### Cards, phones, IPs and versions

* A dotted quad right after a version or clause word is kept as a version
  (`версия прошивки 1.2.3.4`, `п. 4.1.2.3`; a clause part above 30 is an
  address again, so `п. 203.0.113.7` goes). So is one whose first part is at
  most 30 and outside the private ranges after an update verb with `до`/`to`,
  an app or platform name, or a product that numbers its releases in four
  parts (`обновили до 1.1.1.1`, `android 1.1.1.1`, `SDK 12.14.7.228`, `БП
  3.0.150.25`) - unless a network word (`IP`, `сервер`, `host`, `адрес`, and
  `стенд`, `машина`, `агент` in front of the version word) comes earlier in the
  sentence.
* Cards split over a line break are found for your own BINs only.
* A number that begins on something that reads as an amount (`999.12 34 56
  78`, a glued `8999123.45 67`) is removed only with a phone word beside it,
  before the number or right after it (`8999123.45 67 звоните`), and stays
  when it stands alone in a sentence of its own. A seven-digit amount with
  kopecks followed by a two-digit field is read the same way.
* Inside a link the policy keeps, a path number needs a `+` or a query key, so
  a second number glued into such a path stays; `verify` reports it.

### Links and domains

* A bare host with a capitalised word suffix (`Acme.Store`, `Acme.Pay`) is
  read as a product name and kept. Workaround: `custom_patterns`.
* A host typed without a space before the next sentence
  (`romashka.ru.Спасибо`) is not recognised as a host.
* Under `url_mode = "keep"` the host of every link is kept, a host that spells
  a client among them (`romashka.ru`); `verify` reports it, and `url_mode =
  "domain"` hides such a host instead.
* Inside a kept link a value in the path stays even after a keyword segment
  (`/pin/1234`, `/password/Qwerty123`), and so does a long hex or base64 token
  in the path (a password-reset link, like a commit id). `verify` reports
  those, as it reports the host of a nested bare link under `url_mode =
  "keep"`.

### Unicode and line breaks

* A combining mark that composes into a non-Russian letter (`Ромӓшка`),
  overlay marks and a joiner next to a stress mark are not undone, and a
  zero-width joiner next to punctuation stays in the text.
* A value split over a line break stays, and `verify` does not report it,
  since the scrubber never saw the two halves together. The exceptions are a
  labelled SNILS wrapped between its digit groups (`СНИЛС 112-233` + `445 95`)
  and an address wrapped at the `@` - but a Cyrillic word above a line that
  starts with `@` is not read as a local part (`спасибо` + `@mail.ru` stays).
  Transcripts join the lines of a quoted message with a visible `⏎` for the
  same reason, so a reply never changes the verdict.

### Attachments

* An attachment whose file name ends in a tail that is not an extension
  (`Счёт 12. Петров Иван`, `договор.+79991234567`) shows the extension of its
  MIME type instead (`[document:pdf]`), or none at all when Telegram reported
  no type. A tail that is shaped like an extension and survives scrubbing is
  kept, so a stranger's Latin surname can stand there (`отчёт.ivanov`) - the
  same residual as a bare unknown name in text.

### Long identifiers

A run of 40 or more letters, digits, `_`, `-` and `/` is told from a token by
its shape.

* A secret made only of words, numbers and dates is kept like a slug when no
  credential word stands right before it (`логин` or `логином`, `login`,
  `user`, `юзер` or `юзером`, `прокси`, `proxy`, `-u`, `пароль` or `паролем`,
  `password`, `secret`; `после логина` does not count) and no `:password`
  follows it. A bare passphrase such as
  `correct-horse-battery-staple-2026-northwind`, or a residential-proxy login
  alone on its line, therefore stays.
* A lower-case file name or slug keeps an unknown person's Latin name, as
  prose does.
* A known username followed by more words after `_`
  (`export_oleg_support_2026_03_12_payments_report.csv`) stays.

## Over-scrubs

### Names and organisations

* The product name is scrubbed as `<org>` until you add it to `keep_terms`,
  and until then `verify` also reports it inside kept links and longer keep
  terms such as `Northwind Pay`. So is a word from a leftover legacy group
  title (`Новая группа`).
* A two-character product token in a chat title (`S3`, `A4`, `K8`) is scrubbed
  as `<org>` everywhere unless it is in the built-in list (versions `v0`-`v9`,
  tiers `L1`-`L3` and `T1`-`T3`, priorities `P0`-`P4`, quarters `Q1`-`Q4`,
  `H1`, `H2`, `2D`, `3D`, `4K`, `3G`-`5G`, `1С`) or in `keep_terms`.
* A two-character `custom_terms` entry removes the ordinary word it spells
  (`ЯР` also removes `яр`) and is not inflected (`Яру` stays). Write the case
  forms you need as further `custom_terms` entries.
* A surname that is also a common word (`Белый`, `Мороз`, `Лось`, `Король`)
  removes that word too, in every case form including the nominative, and a
  short adjectival one also removes words spelled like one of its forms
  (`Долгий` removes `долгом`). `keep_terms` keeps the word on its own, but the
  person's full name is still removed as a whole: a staff account named `Анна`
  / `Northwind` loses the phrase `Анна Northwind` even with `Northwind` kept.
* A name with a patronymic typed in capitals takes the capitalised word in
  front of it along (`ПЕРЕВОД ИВАН СЕРГЕЕВИЧ`), and a shouted short-form
  adjective that ends like a female patronymic reads as a name (`ЦЕНА
  УСЛОВНА`).
* A product name that is not in the built-in list is removed as a name after a
  holder word (`держатели Acme Pro`) unless it is in `keep_terms`.

### Passwords and credentials

* A key that merely starts with a password word (`"password_hint": ...`) has
  its value removed too, and so does a password word glued to one lower-case
  word (`password_hunter`). A number that ends the line after an order label
  (`пароль к заказу 90829441`) is read as a password as well.
* A `-p` value is judged by the command that owns it, so an unlisted command's
  project or profile is read as a password (`./deploy.sh -p Prod2026`), while
  a password on the same command as a listed one stays (`git commit -m x -p
  S3cret99`).
* A `word:word` pair whose first half is a default account is read as
  credentials even when neither half is a secret (`test:e2e-ci`), and so is
  one after a credential keyword (`credentials: type:oauth2`). After `доступ`,
  `акк` or `учётка` a camel-case role (`доступ: role:ReadOnly`) and an
  all-digit id (`аккаунт: shop:12345`) are read as credentials too.
* An scp-style git address (`git@github.com:org/repo.git`) becomes
  `<credentials>`.
* Prose quoted between a real `BEGIN` and `END` line is removed with the key.

### Codes, CVV, PIN and expiry

* A short code that arrives with no explanation (`пришёл код 4001 от банка`,
  `банк вернул код 4001`, `return code 4001`), or is explained only by a dash
  or a word after it (`Код 4003 — карта заблокирована`, `по коду 4001 отказ`),
  is still read as a one-time code, and so is a one-time code after an earlier
  error clause (`код ошибки, код 482913` keeps the code).
* An error code with words between the error word and the number (`cvv ошибка
  при оплате 4001`) is still read as a CVV.
* A month with a four-digit year after `срок` (`срок 10 2026`, `срок до
  10.2026`) is read as an expiry.

### Addresses

* A sentence before an address on the same line is removed with it (`адрес
  регистрации не совпадает: г. Алматы, Абая 10` becomes `адрес регистрации
  <address>`), and so is digit-bearing prose that does not open with a prose
  word (`прописка, 2 карты`).
* An adjective after `пер.` is still read as a lane (`пер. входящий 500`).

### Cards, phones and versions

* A bare 13-19 digit number that passes Luhn is masked as a card - one random
  order or transaction id in ten (`заказ 424242**********`) - and an 11-digit
  order id that starts on `7` or `8` reads as a Russian number (`номер заказа
  <phone>`, two in nine). A tax id typed right after an order, ticket or
  transaction label with no tax or requisites word before it (`заявка:
  7700000425`) stays as a reference.
* A bare `на` names no version, so a release number after it is read as an
  address (`откатились на 8.25.6.97`), and a version in a private range is
  read as one too (`обновитесь до 10.15.100.200` becomes `<ip>`). The second
  version of a list is scrubbed (`версии 2.15.3.99 и <ip>`).
* A participant's own number is removed in any grouping at all, and what the
  cut leaves of the run goes through the phone shapes again.

### Links and domains

* File names and dotted code identifiers shaped like hosts (`config.md`,
  `logger.info`, `user.info`) are scrubbed unless listed in `allow_domains`.
* An npm scope outside a package-manager command or a `node_modules/` path
  (`установите пакет @northwind/checkout-sdk`, `"@babel/core"`) is read as a
  handle, and so are a broadcast ping (`@channel`) and a code decorator
  (`@staticmethod`).
* A package version with a pre-release tag (`sdk@1.2.3-beta`) is read as an
  e-mail.
* Text glued to a link without a space counts as part of the link.
* Inside a kept link a query value that looks like a keyword value is removed
  even in a search query (`?q=пароль+не+подходит`), and a value that runs into
  the next query parameter takes it along.

### User agents

* After a user-agent, a Latin parenthesised remark (`(timeout)`) and a few
  Latin words right before a slash token (`see the api/v2`) are read as part
  of it; a trailing word the grammar does not know stays (`<user-agent> wv`).

### Long identifiers

* Inside a long run the document rules stand back and the whole run becomes
  one `<token>` (`passport_4510_123456_ivanov_ivan_1985_scan_final.jpg`),
  because replacing only the number would leave the name beside it. A card
  number is the exception: it is always masked first
  (`refund_424242**********_request_2026_03_12_final`).
* A product identifier right after a credential word (`прокси
  northwind_proxy_pool_v2_eu_west_2026_03_12`) or naming a secret
  (`key_rotation_schedule_northwind_v2_2026_03_12`) is removed.
* An `ALL_CAPS` constant shorter than 40 characters keeps a known organisation
  term (`ERR_ROMASHKA_TIMEOUT`, `ROMASHKA_API_KEY`) while a longer identifier
  does not; a known person's name in either is always removed
  (`WALKER_TIMEOUT`, `SEVEROV_PASSPORT_SCAN_2026_03_12`).
* A long identifier becomes `<token>` when it holds a lone letter between
  separators (`get-a-quote-landing-2026-03-12-v2-northwind`), a camelCase
  chunk of one letter (`getAValue2026...`, `iOS_...`), a number of five or
  more digits that is neither a date on its own nor a whole path segment
  (`payouts-export-2026-03-12-merchant-12345-final.csv`,
  `ORDER_REF_TXN20260312_...`,
  `backup_northwind_payments_db_202603121530_final`, while
  `backup_northwind_payments_db_20260312_153000_final` stays), or seven or
  more digits split by separators that are not a date and time.
* After `token` a REST path with a number of seven or more digits is removed
  whole, and so is a value with a single slash (`token:
  v2/northwind_refresh_2026`) unless the keyword is itself a path segment
  (`/api/v2/oauth/token/refresh/2026-03-12` stays).

## Verify limits

* `verify` hunts people's names and chat-title words only in the free-text
  fields of the JSON files. It does not hunt names in the `users.json` display
  names, which `name_mode` decides: under `name_mode = "full"` they hold full
  names on purpose, and the anonymizer has already dropped every display name
  the people vocabulary spells, so an unknown person's Latin name is the
  residual that can stand there.
* Transcripts are checked part by part for the other classes only, since each
  of their lines repeats audited JSON fields; the whole message text in
  `messages.jsonl` is scanned in one piece.
* A value split over a line break is not reported, because the scrubber never
  saw the two halves together.
* A version word glued to the handle in front of it (`@orders_botверсия
  2.15.3.1`) protects nothing, so `verify` reports the version as an address.
* Until your product name is in `keep_terms`, `verify` reports it inside kept
  links and longer keep terms such as `Northwind Pay`.
* A forward author's surname that the scrubber left standing is reported for
  you to judge; `custom_terms` clears the report.
