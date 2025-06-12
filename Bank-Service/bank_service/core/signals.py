from django.db.models.signals import pre_save  # Correct import for signals
from django.dispatch import receiver
from .models import Account
from utils.helper import get_secure_unique_id

@receiver(pre_save, sender=Account, dispatch_uid="account_pre_save")
def account_pre_save(sender, instance, **kwargs):
    """
    Signal handler for generating a unique account number
    before saving an Account instance.
    
    Args:
        sender: The model class that sent the signal.
        instance: The Account instance being saved.
        **kwargs: Additional keyword arguments.

    This function generates a unique account number if it's not already set.
    """
    if not instance.account_number:
        instance.account_number = get_secure_unique_id(
            Account,
            max_digits = 10,
            field_name = 'account_number'  
        )

# @receiver(pre_save, sender=CustomerProfile, dispatch_uid="customer_profile_pre_save")
# def customer_profile_pre_save(sender, instance, **kwargs):
    """
    Signal handler for generating a unique customer ID
    before saving a Customer_profile instance.
    Args:
        sender: The model class that sent the signal.
        instance: The Customer_profile instance being saved.
        **kwargs: Additional keyword arguments.
        
    This function generates a unique customer ID if it's not already set.
    """
    # if not instance.customer_id:
    #     instance.customer_id = get_secure_unique_id(
    #         CustomerProfile,
    #         max_digits = 10,
    #         field_name = 'profile_id'
    #     )
  
