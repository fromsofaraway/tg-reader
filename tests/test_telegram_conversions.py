"""Conversions from real Telethon objects (constructed locally, no network)."""

from datetime import datetime, timezone

from telethon import types, utils

from tg_collector.model import (
    FWD_CHANNEL, FWD_HIDDEN, FWD_IMPORTED, FWD_USER, KIND_BOT, KIND_CHANNEL, KIND_GROUP, KIND_PRIVATE,
    KIND_SELF, KIND_SUPERGROUP, SENDER_CHANNEL, SENDER_NONE, SENDER_USER, RawChat,
)
from tg_collector.telegram import GENERAL_TOPIC_ID, _chat, _forward, _media, _message, _reply, _user

NOW = datetime(2024, 5, 1, tzinfo=timezone.utc)


class Dialog:
    def __init__(self, entity, archived=False):
        self.entity = entity
        self.id = utils.get_peer_id(entity)
        self.name = utils.get_display_name(entity)
        self.archived = archived


def user(**kw):
    base = dict(id=5, first_name="Иван", last_name="Петров", username="ivan_p", phone="79991234567", bot=False, deleted=False)
    base.update(kw)
    return types.User(**base)


def test_user_conversion_with_collectible_usernames():
    u = user(usernames=[types.Username("ivan_p", active=True), types.Username("ivan_alt", active=False)])
    raw = _user(u)
    assert raw.username == "ivan_p" and raw.usernames == ("ivan_alt",) and raw.phone == "79991234567"
    assert raw.all_usernames == ("ivan_p", "ivan_alt")


def test_dialog_classification():
    me = user(id=1, is_self=True)
    bot = user(id=2, bot=True)
    chat = types.Chat(id=10, title="Old group", photo=types.ChatPhotoEmpty(), participants_count=3, date=NOW, version=1,
                      migrated_to=types.InputChannel(200, 0))
    left_chat = types.Chat(id=11, title="Left", photo=types.ChatPhotoEmpty(), participants_count=3, date=NOW, version=1, left=True)
    empty_migrate = types.Chat(id=12, title="Odd", photo=types.ChatPhotoEmpty(), participants_count=3, date=NOW, version=1,
                               migrated_to=types.InputChannelEmpty())
    mega = types.Channel(id=200, title="Acme support", photo=types.ChatPhotoEmpty(), date=NOW, megagroup=True,
                         forum=True, username="acme_sup", participants_count=12)
    broadcast = types.Channel(id=201, title="News", photo=types.ChatPhotoEmpty(), date=NOW, broadcast=True, left=True)
    forbidden = types.ChannelForbidden(id=202, access_hash=0, title="Gone", megagroup=True)
    chat_forbidden = types.ChatForbidden(id=13, title="Gone group")

    kinds = {}
    for entity, archived in ((me, False), (bot, False), (chat, True), (left_chat, False), (empty_migrate, False),
                             (mega, False), (broadcast, False), (forbidden, False), (chat_forbidden, False)):
        raw = _chat(Dialog(entity, archived))
        kinds[raw.id] = raw
    assert kinds[1].kind == KIND_SELF and kinds[2].kind == KIND_BOT
    assert kinds[-10].kind == KIND_GROUP and kinds[-10].migrated_to == -1000000000200 and kinds[-10].is_archived
    assert kinds[-11].kind == KIND_GROUP and not kinds[-11].is_accessible
    assert kinds[-12].migrated_to is None and kinds[-12].is_accessible
    m = kinds[-1000000000200]
    assert m.kind == KIND_SUPERGROUP and m.is_forum and m.username == "acme_sup" and m.participant_count == 12
    assert kinds[-1000000000201].kind == KIND_CHANNEL and not kinds[-1000000000201].is_accessible
    assert kinds[-1000000000202].kind == KIND_SUPERGROUP and not kinds[-1000000000202].is_accessible
    assert kinds[-13].kind == KIND_GROUP and not kinds[-13].is_accessible
    assert _chat(Dialog(user(id=3), False)).kind == KIND_PRIVATE


def group():
    return RawChat(id=-1000000000200, kind=KIND_SUPERGROUP, title="Acme", is_forum=False)


def forum():
    return RawChat(id=-1000000000200, kind=KIND_SUPERGROUP, title="Acme", is_forum=True)


def message(**kw):
    base = dict(id=42, peer_id=types.PeerChannel(200), date=NOW, message="hello @ivan_p",
                from_id=types.PeerUser(5))
    base.update(kw)
    return types.Message(**base)


def test_message_conversion_basic_fields():
    msg = message(entities=[types.MessageEntityMention(6, 7), types.MessageEntityTextUrl(0, 5, "https://x.io")],
                  reply_to=types.MessageReplyHeader(reply_to_msg_id=40), edit_date=NOW,
                  fwd_from=types.MessageFwdHeader(date=NOW, from_id=types.PeerUser(7)), grouped_id=99, post_author="A")
    raw = _message(msg, group(), me_id=1)
    assert (raw.id, raw.chat_id, raw.sender_id, raw.sender_kind) == (42, -1000000000200, 5, SENDER_USER)
    assert raw.text == "hello @ivan_p" and raw.reply_to_id == 40 and raw.topic_id is None
    assert [e.type for e in raw.entities] == ["Mention", "TextUrl"] and raw.entities[1].url == "https://x.io"
    assert raw.forward.kind == FWD_USER and raw.forward.from_id == 7
    assert raw.edit_date == NOW and raw.grouped_id == 99 and raw.post_author == "A" and not raw.is_service


def test_message_text_is_raw_not_markdown():
    msg = message(message="see docs", entities=[types.MessageEntityTextUrl(4, 4, "https://secret.example/x"),
                                                  types.MessageEntityMentionName(0, 3, user_id=777)])
    raw = _message(msg, group(), me_id=1)
    assert raw.text == "see docs"
    assert "secret.example" not in raw.text and "777" not in raw.text


def test_service_and_empty_messages():
    service = types.MessageService(id=3, peer_id=types.PeerChannel(200), date=NOW,
                                   action=types.MessageActionChatAddUser([5]), from_id=types.PeerUser(1))
    raw = _message(service, group(), me_id=1)
    assert raw.is_service and raw.action == "ChatAddUser" and raw.text == ""
    assert _message(types.MessageEmpty(id=4, peer_id=types.PeerChannel(200)), group(), me_id=1) is None


def test_sender_kinds():
    anon = _message(message(from_id=types.PeerChannel(200)), group(), me_id=1)
    assert anon.sender_kind == SENDER_CHANNEL and anon.sender_id == -1000000000200
    nobody = _message(message(from_id=None), group(), me_id=1)
    assert nobody.sender_kind == SENDER_NONE and nobody.sender_id is None
    private = RawChat(id=5, kind=KIND_PRIVATE, title="Ivan")
    incoming = _message(message(from_id=None, peer_id=types.PeerUser(5)), private, me_id=1)
    outgoing = _message(message(from_id=None, peer_id=types.PeerUser(5), out=True), private, me_id=1)
    assert incoming.sender_id == 5 and outgoing.sender_id == 1


def test_forum_topics_and_replies():
    # Direct post in a topic: the header points at the topic root, not a real reply.
    direct = message(reply_to=types.MessageReplyHeader(reply_to_msg_id=100, forum_topic=True))
    raw = _message(direct, forum(), me_id=1)
    assert raw.topic_id == 100 and raw.reply_to_id is None
    # Reply inside a topic.
    reply = message(reply_to=types.MessageReplyHeader(reply_to_msg_id=120, forum_topic=True, reply_to_top_id=100))
    raw = _message(reply, forum(), me_id=1)
    assert raw.topic_id == 100 and raw.reply_to_id == 120
    # General topic: no header at all.
    raw = _message(message(reply_to=None), forum(), me_id=1)
    assert raw.topic_id == GENERAL_TOPIC_ID and raw.reply_to_id is None
    # Cross-chat reply is not a reply we can link.
    cross = message(reply_to=types.MessageReplyHeader(reply_to_msg_id=5, reply_to_peer_id=types.PeerChannel(9)))
    assert _reply(cross, False) == (None, None)
    # Story replies carry no message id.
    story = message(reply_to=types.MessageReplyStoryHeader(peer=types.PeerUser(5), story_id=1))
    assert _reply(story, True) == (None, GENERAL_TOPIC_ID)


def test_forward_kinds():
    assert _forward(message(fwd_from=types.MessageFwdHeader(date=NOW, from_name="Hidden Person"))).kind == FWD_HIDDEN
    assert _forward(message(fwd_from=types.MessageFwdHeader(date=NOW, from_id=types.PeerChannel(9)))).kind == FWD_CHANNEL
    imported = _forward(message(fwd_from=types.MessageFwdHeader(date=NOW, imported=True, from_name="WhatsApp guy")))
    assert imported.kind == FWD_IMPORTED and imported.from_name == "WhatsApp guy"
    assert _forward(message()) is None


def doc(attrs, mime="application/octet-stream"):
    return types.MessageMediaDocument(document=types.Document(
        id=1, access_hash=0, file_reference=b"", date=NOW, mime_type=mime, size=1234, dc_id=1, attributes=attrs))


def test_media_classification():
    assert _media(None) is None
    assert _media(types.MessageMediaWebPage(webpage=types.WebPageEmpty(id=1))) is None
    assert _media(types.MessageMediaPhoto()).kind == "photo"
    pdf = _media(doc([types.DocumentAttributeFilename("Договор_Ромашка.pdf")], "application/pdf"))
    assert (pdf.kind, pdf.ext, pdf.file_name, pdf.size) == ("document", "pdf", "Договор_Ромашка.pdf", 1234)
    voice = _media(doc([types.DocumentAttributeAudio(duration=41, voice=True)], "audio/ogg"))
    assert (voice.kind, voice.duration) == ("voice", 41)
    note = _media(doc([types.DocumentAttributeVideo(duration=7, w=1, h=1, round_message=True)], "video/mp4"))
    assert note.kind == "video_note"
    gif = _media(doc([types.DocumentAttributeAnimated(), types.DocumentAttributeVideo(duration=3, w=1, h=1)], "video/mp4"))
    assert gif.kind == "gif"
    sticker = _media(doc([types.DocumentAttributeVideo(duration=3, w=1, h=1),
                          types.DocumentAttributeSticker("", types.InputStickerSetEmpty())], "video/webm"))
    assert sticker.kind == "sticker"
    log = _media(doc([types.DocumentAttributeFilename("export.LOG")], "text/plain"))
    assert (log.kind, log.ext) == ("document", "log")
    noname = _media(doc([], "image/png"))
    assert (noname.kind, noname.ext) == ("document", "png")
    assert _media(types.MessageMediaContact("79990000000", "A", "B", "", 0)).kind == "contact"
    assert _media(types.MessageMediaGeo(types.GeoPointEmpty())).kind == "location"
    poll = types.Poll(id=1, question=types.TextWithEntities("q", []), answers=[], hash=0)
    assert _media(types.MessageMediaPoll(poll, types.PollResults())).kind == "poll"


def test_halting_errors_are_mapped():
    from telethon import errors
    from tg_collector.errors import AccountUnavailable, NotLoggedIn
    from tg_collector.telegram import _halt_for, _system_version
    req = type("Req", (), {"__name__": "GetHistoryRequest"})
    assert isinstance(_halt_for(errors.PeerFloodError(request=req)), AccountUnavailable)
    assert isinstance(_halt_for(errors.FrozenMethodInvalidError(request=req)), AccountUnavailable)
    assert isinstance(_halt_for(errors.UserDeactivatedBanError(request=req)), AccountUnavailable)
    assert isinstance(_halt_for(errors.AuthKeyDuplicatedError(request=req)), NotLoggedIn)
    assert isinstance(_halt_for(errors.SessionRevokedError(request=req)), NotLoggedIn)
    assert _halt_for(errors.FloodWaitError(request=req, capture=30)) is None
    assert _halt_for(errors.ChatAdminRequiredError(request=req)) is None
    assert _system_version() and "-" not in _system_version().split(" ")[-1]


def test_qr_rendering_and_delivery_text():
    from telethon.tl.types import auth
    from tg_collector.telegram import _code_delivery, _render_qr
    art = _render_qr("tg://login?token=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
    assert art.count("\n") > 10 and "█" in art

    class Sent:
        type = auth.SentCodeTypeApp(length=5)
        next_type = auth.CodeTypeSms()
        timeout = 60
    text = _code_delivery(Sent())
    assert "Telegram app" in text and "resend" in text and "SMS" in text
