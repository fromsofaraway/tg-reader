"""Telegram adapter: the only module that talks to Telethon.

``TelegramSource`` exposes five operations and hides everything about MTProto:
session handling and a lock against concurrent use, interactive login
(code + 2FA password), dialog classification (private/bot/group/supergroup/
channel/self, archived, migrated, forbidden), member lists that may be
hidden, discovery of the legacy group a supergroup was migrated from,
flood-wait and transient-error handling with resume, pacing between
requests, and conversion of Telethon objects into the plain records of
``model``. Nothing Telethon-specific leaks past this seam, so every other
module can be exercised with fakes.

Everything here is read-only: no message is sent, no chat joined, no
username resolved, no contact imported, nothing marked as read.

Usage::

    async with TelegramSource(settings.telegram, settings.export) as src:
        me = await src.me()
        chats = await src.list_chats()
        details = await src.inspect(chat)
        async for message, sender in src.messages(chat, after_id=0):
            ...
"""

from __future__ import annotations

import asyncio
import fcntl
import logging
import mimetypes
import platform
import random
import sys
from typing import AsyncIterator, Optional

from telethon import TelegramClient, errors, functions, types, utils

from . import __version__
from .config import ExportTuning, Telegram
from .errors import AccountUnavailable, FloodTooLong, NotLoggedIn, SessionBusy, TakeoutDelayed
from .model import (
    FWD_CHANNEL, FWD_CHAT, FWD_HIDDEN, FWD_IMPORTED, FWD_USER,
    KIND_BOT, KIND_CHANNEL, KIND_GROUP, KIND_PRIVATE, KIND_SELF, KIND_SUPERGROUP,
    SENDER_CHANNEL, SENDER_CHAT, SENDER_NONE, SENDER_USER,
    ChatDetails, Entity, Forward, Media, RawChat, RawMessage, RawUser,
)

log = logging.getLogger(__name__)

GENERAL_TOPIC_ID = 1  # forum "General" topic has no reply header

# Errors after which continuing would only make things worse for the account.
_ACCOUNT_ERRORS = (
    errors.PeerFloodError, errors.UserRestrictedError, errors.FrozenMethodInvalidError,
    errors.FrozenParticipantMissingError, errors.UserDeactivatedBanError, errors.UserDeactivatedError,
)
_SESSION_ERRORS = (errors.AuthKeyDuplicatedError, errors.SessionRevokedError,
                   errors.AuthKeyUnregisteredError, errors.AuthKeyError)


def _halt_for(exc: BaseException) -> Optional[Exception]:
    """Map a Telethon error to a run-halting condition, or None."""
    if isinstance(exc, _ACCOUNT_ERRORS):
        return AccountUnavailable(
            f"Telegram limited the account ({type(exc).__name__}: {exc}). Stop all API use, open @SpamBot "
            "in the official app to see the reason, and do not retry until it is cleared.")
    if isinstance(exc, _SESSION_ERRORS):
        return NotLoggedIn(
            f"The session was invalidated ({type(exc).__name__}). This usually means the same session file was "
            "used from two places at once. Run: tg-collector login (from one machine only).")
    return None


class TelegramSource:
    def __init__(self, tg: Telegram, tuning: ExportTuning, interactive: bool = False):
        """``interactive`` is for ``login``: it keeps the update stream on,
        which the QR-code flow needs to learn that the phone confirmed."""
        tg.require()
        tg.session.parent.mkdir(parents=True, exist_ok=True)
        self._tg = tg
        self._tuning = tuning
        self._me_id: Optional[int] = None
        self._lock_fh = None
        self._takeout = None  # takeout proxy client for the history phase, when enabled
        self._client = TelegramClient(
            str(tg.session), tg.api_id, tg.api_hash,
            # One honest, constant device identity: sessions that change their
            # fingerprint on every run are what gets accounts logged out.
            device_model="tg-collector",
            system_version=_system_version(),
            app_version=f"tg-collector {__version__}",
            flood_sleep_threshold=min(tuning.flood_sleep_threshold, tuning.max_flood_wait),
            raise_last_call_error=True,
            request_retries=3,
            connection_retries=10,
            retry_delay=5,
            auto_reconnect=True,
            receive_updates=interactive,  # exports need no update stream; QR login does
        )
        self._client.parse_mode = None  # never let Telethon render markdown into text

    async def __aenter__(self) -> "TelegramSource":
        self._acquire_lock()
        try:
            await self._client.connect()
        except errors.AuthKeyError as exc:
            raise NotLoggedIn(f"Telegram rejected the session key ({exc}); delete {self._tg.session}.session "
                              "and run: tg-collector login") from exc
        return self

    async def __aexit__(self, *exc) -> None:
        try:
            if self._takeout is not None:
                await self._takeout.__aexit__(None, None, None)  # finalize=False: the takeout id is kept
        finally:
            await self._client.disconnect()
            if self._lock_fh is not None:
                fcntl.flock(self._lock_fh, fcntl.LOCK_UN)
                self._lock_fh.close()
                self._lock_fh = None

    async def _history_client(self):
        """The client used for history reads: the plain client, or Telegram's
        data-export (takeout) session when enabled. A takeout id is created
        once and reused by later runs; Telegram may first ask the owner to
        confirm the export on another device (``TakeoutDelayed``)."""
        if not self._tuning.takeout:
            return self._client
        if self._takeout is None:
            if self._client.session.takeout_id is None:
                proxy = self._client.takeout(finalize=False, users=True, chats=True, megagroups=True, channels=True)
            else:
                proxy = self._client.takeout(finalize=False)
            try:
                await proxy.__aenter__()
            except errors.TakeoutInitDelayError as exc:
                raise TakeoutDelayed(exc.seconds) from exc
            self._takeout = proxy
        return self._takeout

    def _acquire_lock(self) -> None:
        lock_path = self._tg.session.with_suffix(".lock")
        fh = open(lock_path, "w")
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            fh.close()
            raise SessionBusy(f"another tg-collector process is using {self._tg.session}") from exc
        self._lock_fh = fh

    # --- auth ------------------------------------------------------------------------

    async def login(self, qr: bool = False) -> RawUser:
        """Interactive. Two ways in: a login code (Telegram delivers it to the
        app, by SMS or by call; can be re-sent another way) or a QR code
        scanned from an already logged-in official app (no code at all).
        The 2FA password is asked on the terminal when enabled."""
        if not sys.stdin.isatty():
            raise NotLoggedIn("login needs an interactive terminal (Telegram sends a code to confirm)")
        if await self._client.is_user_authorized():
            return await self.me()
        if qr:
            await self._qr_login()
            return await self.me()
        phone = self._tg.phone or input("Phone (international format, e.g. +12025550143): ").strip()
        try:
            sent = await self._client.send_code_request(phone)
        except (errors.PhoneNumberInvalidError, errors.PhoneNumberBannedError, errors.PhoneNumberFloodError,
                errors.SendCodeUnavailableError) as exc:
            raise NotLoggedIn(f"Telegram refused to send a code to {phone}: {type(exc).__name__}. "
                              "Check the number (with country code) and log into the account in the official app first.") from exc
        _say(_code_delivery(sent))
        while True:
            code = input("Code (or 'resend' to get it another way, 'qr' to scan a QR code instead): ").strip()
            if code.lower() == "qr":
                await self._qr_login()
                return await self.me()
            if code.lower() in ("resend", "again", "sms", "call"):
                try:
                    sent = await self._client.send_code_request(phone)  # re-sends via sent.next_type
                except errors.FloodError as exc:
                    raise NotLoggedIn(f"Too many code requests; Telegram asks to wait {getattr(exc, 'seconds', '?')} s.") from exc
                _say(_code_delivery(sent))
                continue
            if not code:
                continue
            try:
                await self._client.sign_in(phone, code, phone_code_hash=sent.phone_code_hash)
                break
            except errors.SessionPasswordNeededError:
                import getpass
                for _ in range(3):
                    try:
                        await self._client.sign_in(password=getpass.getpass("Two-step verification password: "))
                        break
                    except errors.PasswordHashInvalidError:
                        _say("Wrong password, try again.")
                else:
                    raise NotLoggedIn("Two-step verification password rejected three times.")
                break
            except errors.PhoneCodeInvalidError:
                _say("The code is wrong. Check it and try again, or type 'resend'.")
            except errors.PhoneCodeExpiredError:
                _say("The code expired; requesting a new one.")
                sent = await self._client.send_code_request(phone)
                _say(_code_delivery(sent))
        return await self.me()

    async def _qr_login(self) -> None:
        """Log in by showing a QR code that the user scans in the official
        app (Settings -> Devices -> Link Desktop Device). Tokens live about
        30 seconds; a fresh one is drawn until the phone confirms."""
        _say("Open Telegram on the phone where the account is logged in: Settings -> Devices -> "
             "Link Desktop Device, and scan the code below. A new code is drawn when the old one expires.")
        qr = await self._client.qr_login()
        while True:
            _say("\n" + _render_qr(qr.url) + "\n(waiting for the scan ... press Ctrl+C to give up)")
            try:
                await qr.wait(timeout=max(10.0, (qr.expires - _now()).total_seconds()))
                return
            except asyncio.TimeoutError:
                await self._pause(1)
                await qr.recreate()
            except errors.SessionPasswordNeededError:
                import getpass
                for _ in range(3):
                    try:
                        await self._client.sign_in(password=getpass.getpass("Two-step verification password: "))
                        return
                    except errors.PasswordHashInvalidError:
                        _say("Wrong password, try again.")
                raise NotLoggedIn("Two-step verification password rejected three times.")

    async def me(self) -> RawUser:
        try:
            if not await self._client.is_user_authorized():
                raise NotLoggedIn("Session is not authorized. Run: tg-collector login")
            user = await self._client.get_me()
        except errors.RPCError as exc:
            halt = _halt_for(exc)
            if halt is not None:
                raise halt from exc
            if isinstance(exc, errors.UnauthorizedError):
                raise NotLoggedIn(f"Session rejected by Telegram ({type(exc).__name__}). Run: tg-collector login") from exc
            raise
        if user is None:
            raise NotLoggedIn("Session is not authorized. Run: tg-collector login")
        self._me_id = user.id
        return _user(user)

    # --- dialogs ---------------------------------------------------------------------

    async def list_chats(self) -> list[RawChat]:
        """Every dialog of the account, including archived ones and legacy
        groups that migrated to a supergroup (marked via ``migrated_to``)."""
        chats: list[RawChat] = []
        async for dialog in self._client.iter_dialogs(ignore_migrated=False):
            chat = _chat(dialog)
            if chat is not None:
                chats.append(chat)
        return chats

    async def inspect(self, chat: RawChat) -> ChatDetails:
        """Members and lineage of a group in one or two requests. Never
        raises for a chat that merely hides its member list; see ``error``."""
        await self._pause(self._tuning.participants_wait)
        try:
            entity = await self._client.get_input_entity(chat.id)
            count = chat.participant_count
            migrated_from = None
            if chat.kind in (KIND_SUPERGROUP, KIND_CHANNEL):
                full = await self._call(functions.channels.GetFullChannelRequest(entity))
                fc = full.full_chat
                count = fc.participants_count if fc.participants_count is not None else count
                if fc.migrated_from_chat_id:
                    migrated_from = utils.get_peer_id(types.PeerChat(fc.migrated_from_chat_id))
                if fc.can_view_participants is False:
                    return ChatDetails(complete=False, error="participants hidden",
                                       participants_count=count, migrated_from_id=migrated_from)
                await self._pause(self._tuning.participants_wait)
            found = await self._call_participants(entity)
            users = [_user(u) for u in found if isinstance(u, types.User)]
            total = getattr(found, "total", None)
            complete = total is not None and len(found) >= total
            return ChatDetails(users=users, complete=complete, participants_count=total or count,
                               migrated_from_id=migrated_from)
        except errors.RPCError as exc:
            halt = _halt_for(exc)
            if halt is not None:
                raise halt from exc
            # ChatAdminRequired, ChannelPrivate, ChannelInvalid, ChatForbidden ...:
            # a hidden or inaccessible member list is a normal outcome.
            log.warning("members of %s unavailable: %s", chat.id, type(exc).__name__)
            return ChatDetails(error=type(exc).__name__, participants_count=chat.participant_count)

    # --- messages -----------------------------------------------------------------------

    async def messages(self, chat: RawChat, after_id: int = 0) -> AsyncIterator[tuple[RawMessage, Optional[RawUser]]]:
        """Messages newer than ``after_id`` in ascending order, each with its
        sender when Telegram returned the user object. Flood waits are slept
        through in full; transient errors are retried with backoff; the
        iteration always resumes after the last delivered id."""
        entity = await self._client.get_input_entity(chat.id)
        client = await self._history_client()
        await self._pause(self._tuning.chat_wait)
        last_id = after_id
        failures = 0
        while True:
            try:
                if not self._client.is_connected():
                    await self._client.connect()
                async for msg in client.iter_messages(
                    entity, reverse=True, min_id=last_id, wait_time=self._tuning.wait_time,
                ):
                    raw = _message(msg, chat, self._me_id)
                    if raw is None:
                        continue
                    sender = msg.sender if isinstance(msg.sender, types.User) else None
                    last_id = raw.id
                    failures = 0
                    yield raw, _user(sender) if sender else None
                return
            except errors.TakeoutInvalidError as exc:
                # The stored takeout session expired on the server: forget it
                # and let the next run start a fresh one (possibly with a delay).
                self._client.session.takeout_id = None
                self._takeout = None
                raise TakeoutDelayed(0) from exc
            except errors.FloodError as exc:
                halt = _halt_for(exc)
                if halt is not None:
                    raise halt from exc
                seconds = getattr(exc, "seconds", 60) or 60
                if seconds > self._tuning.max_flood_wait:
                    raise FloodTooLong(seconds, self._tuning.max_flood_wait) from exc
                log.warning("flood wait %ss in chat %s, resuming after id %s", seconds, chat.id, last_id)
                await asyncio.sleep(seconds + random.uniform(1, 5))
            except (errors.ServerError, errors.TimedOutError) as exc:
                failures += 1
                if failures > self._tuning.max_retries:
                    raise
                delay = min(300, 5 * 2 ** failures) + random.uniform(0, 5)
                log.warning("%s in chat %s (attempt %s), retrying in %.0fs", type(exc).__name__, chat.id, failures, delay)
                await asyncio.sleep(delay)
            except errors.RPCError as exc:
                halt = _halt_for(exc)
                if halt is not None:
                    raise halt from exc
                raise
            except (OSError, asyncio.TimeoutError) as exc:
                failures += 1
                if failures > self._tuning.max_retries:
                    raise
                delay = min(300, 5 * 2 ** failures) + random.uniform(0, 5)
                log.warning("%s in chat %s (attempt %s), retrying in %.0fs", type(exc).__name__, chat.id, failures, delay)
                await asyncio.sleep(delay)

    # --- internals ----------------------------------------------------------------------

    async def _pause(self, seconds: float) -> None:
        if seconds > 0:
            await asyncio.sleep(seconds + random.uniform(0, seconds / 2))

    async def _call(self, request, attempts: int = 3):
        """One RPC call that sleeps through flood waits and retries transient errors."""
        return await self._retrying(lambda: self._client(request), type(request).__name__, attempts)

    async def _call_participants(self, entity):
        return await self._retrying(lambda: self._client.get_participants(entity), "GetParticipants", 3)

    async def _retrying(self, call, label: str, attempts: int):
        failures = 0
        while True:
            try:
                return await call()
            except errors.FloodError as exc:
                halt = _halt_for(exc)
                if halt is not None:
                    raise halt from exc
                seconds = getattr(exc, "seconds", 60) or 60
                if seconds > self._tuning.max_flood_wait:
                    raise FloodTooLong(seconds, self._tuning.max_flood_wait) from exc
                log.warning("flood wait %ss on %s", seconds, label)
                await asyncio.sleep(seconds + random.uniform(1, 5))
            except (errors.ServerError, errors.TimedOutError, OSError, asyncio.TimeoutError):
                failures += 1
                if failures >= attempts:
                    raise
                await asyncio.sleep(min(300, 5 * 2 ** failures))


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _now():
    import datetime
    return datetime.datetime.now(tz=datetime.timezone.utc)


def _render_qr(url: str) -> str:
    """The login URL as a terminal QR code (half-block characters)."""
    import io
    import qrcode
    code = qrcode.QRCode(border=1)
    code.add_data(url)
    code.make(fit=True)
    buf = io.StringIO()
    code.print_ascii(out=buf, invert=True)
    return buf.getvalue()


_DELIVERY = {
    "SentCodeTypeApp": "the Telegram app on a device where this account is already logged in: open the chat "
                       "named 'Telegram' (service notifications) and copy the login code",
    "SentCodeTypeSms": "SMS to the phone number",
    "SentCodeTypeCall": "a phone call that dictates the code",
    "SentCodeTypeFlashCall": "a missed call: the code is the last digits of the calling number",
    "SentCodeTypeMissedCall": "a missed call: the code is the last digits of the calling number",
    "SentCodeTypeFragmentSms": "fragment.com (anonymous number): open the Fragment site to read the code",
    "SentCodeTypeEmailCode": "the login e-mail configured for this account",
    "SentCodeTypeSetUpEmailRequired": "nowhere: Telegram wants a login e-mail set up in the official app first",
    "SentCodeTypeSmsWord": "SMS containing a word to type",
    "SentCodeTypeSmsPhrase": "SMS containing a phrase to type",
}
_NEXT = {
    "CodeTypeSms": "SMS", "CodeTypeCall": "a phone call", "CodeTypeFlashCall": "a missed call",
    "CodeTypeMissedCall": "a missed call", "CodeTypeFragmentSms": "fragment.com",
}


def _code_delivery(sent) -> str:
    """Operator-facing description of where the login code went."""
    kind = type(sent.type).__name__
    where = _DELIVERY.get(kind, kind)
    text = f"Telegram sent the login code via {where}."
    nxt = type(sent.next_type).__name__ if getattr(sent, "next_type", None) else None
    if nxt:
        text += f" If it does not arrive, type 'resend' to get it via {_NEXT.get(nxt, nxt)}."
    if getattr(sent, "timeout", None):
        text += f" (resend possible after {sent.timeout} s)"
    return text


def _system_version() -> str:
    """A plain, stable OS description (odd kernel strings have caused mass logouts)."""
    system = platform.system() or "unknown"
    if system == "Darwin":
        return f"macOS {platform.mac_ver()[0] or ''}".strip()
    return f"{system} {platform.release()}".strip()


# --- conversions ----------------------------------------------------------------------------

def _user(u: types.User) -> RawUser:
    extra = tuple(x.username for x in (u.usernames or ()) if getattr(x, "username", None))
    return RawUser(
        id=u.id,
        first_name=u.first_name or "",
        last_name=u.last_name or "",
        username=u.username or "",
        phone=u.phone or "",
        is_bot=bool(u.bot),
        is_deleted=bool(u.deleted),
        usernames=tuple(x for x in extra if x != u.username),
    )


def _chat(dialog) -> Optional[RawChat]:
    e = dialog.entity
    base = dict(id=dialog.id, title=dialog.name or "", is_archived=bool(dialog.archived))
    if isinstance(e, types.User):
        kind = KIND_SELF if e.is_self else KIND_BOT if e.bot else KIND_PRIVATE
        return RawChat(kind=kind, username=e.username or "", **base)
    if isinstance(e, types.Chat):
        migrated = None
        channel_id = getattr(e.migrated_to, "channel_id", None)  # InputChannelEmpty has none
        if channel_id:
            migrated = utils.get_peer_id(types.PeerChannel(channel_id))
        # A deactivated (migrated) group still serves its old history.
        return RawChat(kind=KIND_GROUP, migrated_to=migrated, is_accessible=not e.left,
                       participant_count=e.participants_count, **base)
    if isinstance(e, types.ChatForbidden):
        return RawChat(kind=KIND_GROUP, is_accessible=False, **base)
    if isinstance(e, types.Channel):
        kind = KIND_SUPERGROUP if e.megagroup else KIND_CHANNEL
        return RawChat(kind=kind, username=e.username or "", is_forum=bool(e.forum),
                       is_accessible=not e.left, participant_count=e.participants_count, **base)
    if isinstance(e, types.ChannelForbidden):
        return RawChat(kind=KIND_SUPERGROUP if e.megagroup else KIND_CHANNEL, is_accessible=False, **base)
    return None


def _peer_id(peer) -> Optional[int]:
    return utils.get_peer_id(peer) if peer is not None else None


def _sender(msg, chat: RawChat, me_id: Optional[int]) -> tuple[Optional[int], str]:
    peer = msg.from_id
    if peer is None and chat.kind in (KIND_PRIVATE, KIND_BOT):
        # Private dialogs omit from_id: the counterpart wrote it, or we did.
        return (me_id if getattr(msg, "out", False) else chat.id), SENDER_USER
    if isinstance(peer, types.PeerUser):
        return peer.user_id, SENDER_USER
    if isinstance(peer, types.PeerChat):
        return utils.get_peer_id(peer), SENDER_CHAT
    if isinstance(peer, types.PeerChannel):
        return utils.get_peer_id(peer), SENDER_CHANNEL
    return None, SENDER_NONE


def _entities(msg) -> tuple[Entity, ...]:
    out = []
    for e in msg.entities or ():
        out.append(Entity(
            type=type(e).__name__.removeprefix("MessageEntity"),
            offset=e.offset, length=e.length,
            url=getattr(e, "url", None), user_id=getattr(e, "user_id", None),
        ))
    return tuple(out)


def _reply(msg, is_forum: bool) -> tuple[Optional[int], Optional[int]]:
    """(reply_to_id, topic_id). In forums the header also encodes the topic:
    a plain post in a topic 'replies' to the topic root, which is not a real
    reply, and posts in General carry no header at all."""
    h = msg.reply_to
    if not isinstance(h, types.MessageReplyHeader):
        return None, (GENERAL_TOPIC_ID if is_forum else None)
    if h.forum_topic:  # the header's own flag: set even if the chat became a forum after listing
        topic = h.reply_to_top_id or h.reply_to_msg_id
        reply = h.reply_to_msg_id if h.reply_to_top_id else None
    else:
        topic = GENERAL_TOPIC_ID if is_forum else None
        reply = h.reply_to_msg_id
    if h.reply_to_peer_id is not None or reply == topic:
        reply = None
    return reply, topic


def _forward(msg) -> Optional[Forward]:
    f = msg.fwd_from
    if f is None:
        return None
    if getattr(f, "imported", False):
        kind = FWD_IMPORTED
    elif isinstance(f.from_id, types.PeerUser):
        kind = FWD_USER
    elif isinstance(f.from_id, types.PeerChat):
        kind = FWD_CHAT
    elif isinstance(f.from_id, types.PeerChannel):
        kind = FWD_CHANNEL
    else:
        kind = FWD_HIDDEN
    return Forward(kind=kind, from_id=_peer_id(f.from_id), from_name=f.from_name or "", date=f.date)


def _media(media) -> Optional[Media]:
    if media is None or isinstance(media, types.MessageMediaWebPage):
        return None
    if isinstance(media, types.MessageMediaPhoto):
        return Media(kind="photo", ext="jpg")
    if isinstance(media, types.MessageMediaDocument):
        doc = media.document
        if not isinstance(doc, types.Document):
            return Media(kind="document")
        kind = "document"
        if getattr(media, "voice", False):
            kind = "voice"
        elif getattr(media, "round", False):
            kind = "video_note"
        name = ""
        duration = None
        attr_kind = None
        for attr in doc.attributes:
            if isinstance(attr, types.DocumentAttributeSticker):
                attr_kind = "sticker"
            elif isinstance(attr, types.DocumentAttributeAnimated):
                attr_kind = attr_kind or "gif"
            elif isinstance(attr, types.DocumentAttributeAudio):
                attr_kind = attr_kind or ("voice" if attr.voice else "audio")
                duration = int(attr.duration or 0) or duration
            elif isinstance(attr, types.DocumentAttributeVideo):
                attr_kind = attr_kind or ("video_note" if attr.round_message else "video")
                duration = int(attr.duration or 0) or duration
            elif isinstance(attr, types.DocumentAttributeFilename):
                name = attr.file_name or ""
        if kind == "document" and attr_kind:
            kind = attr_kind
        if "." in name:
            ext = name.rsplit(".", 1)[-1].lower()
        else:
            ext = (mimetypes.guess_extension(doc.mime_type or "") or "").lstrip(".")
        return Media(kind=kind, ext=ext, mime=doc.mime_type or "", size=doc.size, duration=duration, file_name=name)
    if isinstance(media, types.MessageMediaContact):
        return Media(kind="contact")
    if isinstance(media, (types.MessageMediaGeo, types.MessageMediaGeoLive, types.MessageMediaVenue)):
        return Media(kind="location")
    if isinstance(media, types.MessageMediaPoll):
        return Media(kind="poll")
    return Media(kind="other")


def _message(msg, chat: RawChat, me_id: Optional[int]) -> Optional[RawMessage]:
    if isinstance(msg, types.MessageEmpty) or msg.date is None:
        return None
    sender_id, sender_kind = _sender(msg, chat, me_id)
    reply_to, topic = _reply(msg, chat.is_forum)
    action = getattr(msg, "action", None)
    return RawMessage(
        chat_id=chat.id,
        id=msg.id,
        date=msg.date,
        sender_id=sender_id,
        sender_kind=sender_kind,
        text=msg.message or "",  # raw text; never msg.text (that renders markdown)
        entities=_entities(msg),
        reply_to_id=reply_to,
        topic_id=topic,
        forward=_forward(msg),
        media=_media(getattr(msg, "media", None)),
        action=type(action).__name__.removeprefix("MessageAction") if action is not None else None,
        edit_date=getattr(msg, "edit_date", None),
        grouped_id=getattr(msg, "grouped_id", None),
        via_bot_id=getattr(msg, "via_bot_id", None),
        post_author=getattr(msg, "post_author", None) or "",
    )
