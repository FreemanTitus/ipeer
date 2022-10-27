from .models import MessageModel, Room, UserModel, UploadedFile
from typing import Optional, Dict
import os


def serialize_file_model(m: UploadedFile) -> Dict[str, str]:
    return {
        'id': str(m.id),
        'url': m.file.url,
        'size': m.file.size,
        'name': os.path.basename(m.file.name)
    }


def serializer_message_model(m: MessageModel, user_id):
    sender_pk = m.sender.pk
    is_out = sender_pk == user_id
    # TODO: add forwards
    # TODO: add replies
    obj = {
        "id": m.id,
        "text": m.text,
        "sent": int(m.created.timestamp()),
        "edited": int(m.modified.timestamp()),
        "read": m.read,
        "file": serialize_file_model(m.file) if m.file else None,
        "sender": str(sender_pk),
        "receiver": str(m.receiver.pk),
        "out": is_out,
        "sender_username": m.sender.get_username()
    }
    return obj


def serialize_room_model(m: Room, user_id):
    username_field = UserModel.USERNAME_FIELD
    other_user_pk, other_user_username = UserModel.objects.filter(pk=m.user1.pk).values_list('pk',
                                                                                             username_field).first() \
        if m.user2.pk == user_id else UserModel.objects.filter(pk=m.user2.pk).values('pk', username_field).first()

    unread_count = MessageModel.get_unread_count_for_room_with_user(sender=other_user_pk, receiver=user_id)
    last_message: Optional[MessageModel] = MessageModel.get_last_message_for_room(
        sender=other_user_pk, receiver=user_id)
    last_message_ser = serializer_message_model(last_message, user_id) if last_message else None
    obj = {
        "id": m.id,
        "created": int(m.created.timestamp()),
        "modified": int(m.modified.timestamp()),
        "other_user_id": str(other_user_pk),
        "unread_count": unread_count,
        "username": other_user_username,
        "last_message": last_message_ser
    }
    return obj
