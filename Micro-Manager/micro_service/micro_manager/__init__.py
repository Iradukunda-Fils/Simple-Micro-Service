# from django.apps import apps as django_apps
# from .settings import api_settings
# from django.core.exceptions import ImproperlyConfigured
# from django.utils import timezone
 

# def get_service_model():
#     """
#     Return the User model that is active in this project.
#     """
#     try:
#         return django_apps.get_model(api_settings.SERVICES_MODEL, require_ready=False)
#     except ValueError:
#         raise ImproperlyConfigured(
#             "SERVICES_MODEL must be of the form 'app_label.model_name'"
#         )
#     except LookupError:
#         raise ImproperlyConfigured(
#             "SERVICE_MODEL refers to model '%s' that has not been installed"
#             % api_settings.SERVICES_MODEL
#         )
        

# def update_last_login(sender, service, **kwargs):
#     """
#     A signal receiver which updates the last_login date for
#     the user logging in.
#     """
#     service.last_login = timezone.now()
#     service.save(update_fields=["last_login"])