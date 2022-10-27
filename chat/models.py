import uuid
from typing import Optional, Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.timezone import localtime
from django.db import models
from django.db.models import Q
from model_utils.models import TimeStampedModel, SoftDeletableModel

UserModel: AbstractBaseUser = get_user_model()


def user_directory_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/user_<id>/<filename>
    return f"user_{instance.uploaded_by.pk}/{filename}"


class UploadedFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, verbose_name="Uploaded_by",
                                    related_name='+', db_index=True)
    file = models.FileField(verbose_name="File", blank=False, null=False, upload_to=user_directory_path)
    upload_date = models.DateTimeField(auto_now_add=True, verbose_name="Upload date")

    def __str__(self):
        return str(self.file.name)


class Room(models.Model):
    """ A private room for people to chat in."""
    name = models.CharField(max_length=255)
    user1 = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='user1')
    user2 = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='user2')
    slug = models.SlugField(unique=True)
    # Users who are currently connected to the socket (Used to keep track of unread messages)
    connected_users = models.ManyToManyField(settings.AUTH_USER_MODEL, blank=True, related_name="connected_users")
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = (('user1', 'user2'), ('user2', 'user1'))
        verbose_name = "Room"
        verbose_name_plural = 'Rooms'

    def connected_user(self, user):
        """ return true if user is added to the connected_user"""
        is_user_added = False
        if not user in self.connected_users.all():
            self.connected_users.add(user)
            is_user_added = True
        return is_user_added

    def disconnect_user(self, user):
        """ return true if user is removed from the connected_users."""
        is_user_removed = False
        if user in self.connected_users.all():
            self.connected_users.remove(user)
            is_user_removed = True
        return is_user_removed

    @property
    def group_name(self):
        """ Returns the Channels Group name that socket should subscribe to, to get sent
        messages as they are generated.
        """
        return f'Room-{self.name}'

    def __str__(self):
        return "Room between" + f'{self.user1.pk}, {self.user2.pk}'

    @staticmethod
    def room_exists(u1: AbstractBaseUser, u2: AbstractBaseUser) -> Optional[Any]:
        return Room.objects.filter(Q(user1=u1, user2=u2) | Q(user1=u2, user2=u1)).first()

    @staticmethod
    def create_if_not_exists(u1: AbstractBaseUser, u2: AbstractBaseUser):
        res = Room.room_exists(u1, u2)
        if not res:
            Room.objects.create(user1=u1, user2=u2)

    @staticmethod
    def get_rooms_for_user(user: AbstractBaseUser):
        return Room.objects.filter(Q(user1=user) | Q(user2=user)).values_list('user1__pk', 'user2__pk')


class MessageModel(TimeStampedModel, SoftDeletableModel):
    id = models.BigAutoField(primary_key=True, verbose_name="ID")
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                               verbose_name="Author", related_name="from_user", db_index=True)
    receiver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                 verbose_name="Receiver", related_name="to_user", db_index=True)
    # room = models.ForeignKey(Room, related_name='messages', on_delete=models.CASCADE)
    # user = models.ForeignKey(User, related_name='messages', on_delete=models.CASCADE)
    text = models.TextField(verbose_name="Text", blank=True)
    file = models.ForeignKey(UploadedFile, related_name='message', on_delete=models.DO_NOTHING,
                             verbose_name="File", blank=True, null=True)
    read = models.BooleanField(verbose_name='Read', default=False)
    all_objects = models.Manager()

    @staticmethod
    def get_unread_count_for_room_with_user(sender, receiver):
        return MessageModel.objects.filter(sender_id=sender, receiver_id=receiver, read=False).count()

    @staticmethod
    def get_last_message_for_room(sender, receiver):
        return MessageModel.objects.filter(
            Q(sender_id=sender, receiver_id=receiver) | Q(sender_id=receiver, receiver_id=sender)) \
            .select_related('sender', 'receiver').first()

    def __str__(self):
        return str(self.pk)

    def save(self, *args, **kwargs):
        super(MessageModel, self).save(*args, **kwargs)
        Room.create_if_not_exists(self.sender, self.receiver)

    class Meta:
        ordering = ['-created']
        verbose_name = "Message"
        verbose_name_plural = "Messages"

