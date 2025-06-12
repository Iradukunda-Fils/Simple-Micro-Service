from django.dispatch import receiver
from django.contrib.auth import get_user_model
from utils.helper import get_secure_unique_id

User = get_user_model()

@receiver(presave, sender=User, dispatch_uid='user_pre_save_profile')
def pre_save_profile(sender, instance, **kwargs):
    """
    Pre-save signal hander for the User model.
    This signal handler listens for the presave signal of the User model.
    Args:
        sender: The model class that sent the signal (User).
        instance: The instance of the model that is about to be saved.
        **kwargs: Additional keyword arguments.
    Returns:
        None
    """
    if not instance.user_id: 
        instance.user_id = get_secure_unique_id(
            User, 
            max_digits = 10,
            field_name ='user_id'
            )

# @receiver(post_save, sender=User, dispatch_uid='user_post_save_profile')
# def create_profile(sender, instance, created, **kwargs):
#     """
#     Create a Profile instance for the User instance after it is created.
#     This signal handler listens for the post_save signal of the User model.
    
#     Args:
#         sender: The model class that sent the signal (User).
#         instance: The instance of the model that was saved.
#         created: A boolean indicating whether a new instance was created.
#         **kwargs: Additional keyword arguments.
#     Returns:
#         None
#     """
#     user_group = instance.groups.filter(name='employees').first()
#     if created:
#         Profile.objects.create(user=instance)
    