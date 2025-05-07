# # from django.apps import AppConfig
# # from django.contrib.auth.hashers import make_password
# # from django.conf import settings


# # class ApiConfig(AppConfig):
# #     default_auto_field = "django.db.models.BigAutoField"
# #     name = "api"

# #     def ready(self):
# #         from .models import User

# #         if (
# #             settings.ADMIN_EMAIL
# #             and not User.objects.filter(email=settings.ADMIN_EMAIL).exists()
# #         ):
# #             User.objects.create(
# #                 name=settings.ADMIN_NAME,
# #                 email=settings.ADMIN_EMAIL,
# #                 phone_number=settings.ADMIN_PHONE,
# #                 password=make_password(settings.ADMIN_PASSWORD),
# #                 is_superuser=True,
# #                 is_staff=True,
# #                 is_active=True,
# #             )


from django.apps import AppConfig
from django.contrib.auth.hashers import make_password
from django.conf import settings
from django.db import OperationalError, connections
from django.db.migrations.executor import MigrationExecutor


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"

    def ready(self):
        from .models import User

        # Check if migrations have been applied
        try:
            connection = connections['default']
            if not connection.settings_dict.get('NAME'):
                return  # Skip if no database is configured

            executor = MigrationExecutor(connection)
            if executor.migration_plan(executor.loader.graph.leaf_nodes()):
                return  # Skip if migrations are pending

            # Create the admin user if it doesn't exist
            if (
                settings.ADMIN_EMAIL
                and not User.objects.filter(email=settings.ADMIN_EMAIL).exists()
            ):
                User.objects.create(
                    name=settings.ADMIN_NAME,
                    email=settings.ADMIN_EMAIL,
                    phone_number=settings.ADMIN_PHONE,
                    password=make_password(settings.ADMIN_PASSWORD),
                    is_superuser=True,
                    is_staff=True,
                    is_active=True,
                )
        except OperationalError:
            # Skip if the database is not ready
            pass


# class ApiConfig(AppConfig):
#     default_auto_field = "django.db.models.BigAutoField"
#     name = "api"

#     def ready(self):
#         pass  # Temporarily disable the ready method