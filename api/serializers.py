from rest_framework import serializers

from django.contrib.auth.hashers import make_password
import re
from .models import User, Person
from .models import User


class SignupSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            "name",
            "email",
            "phone_number",
            "gender",
            "password",
            "confirm_password",
        ]

    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError(
                "Password and confirm password must be the same."
            )
        return data

    def validate_name(self, value):
        if not re.match("^[a-zA-Z ]*$", value):
            raise serializers.ValidationError("Name cannot contain special characters.")
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value

    def validate_phone_number(self, value):
        if not re.match(r"^[0-9]{10,15}$", value):
            raise serializers.ValidationError("Enter a valid phone number.")
        if User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("Phone number already exists.")
        return value

    def validate_password(self, value):
        if not re.match(
            r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            value,
        ):
            raise serializers.ValidationError(
                "Password must contain at least 8 characters, one uppercase, one lowercase, one digit, and one special character."
            )
        return value

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        validated_data["password"] = make_password(validated_data["password"])
        return User.objects.create(**validated_data)


class PersonSerializer(serializers.ModelSerializer):
    # Explicit field declarations help to enforce requirements and validations.
    name = serializers.CharField(required=True, max_length=100)
    # age = serializers.IntegerField(required=True)
    email = serializers.EmailField(required=True)

    class Meta:
        model = Person
        # Included the auto-generated primary key (id) in responses.
        fields = ("id", "name", "age", "email")


class SocialAuthSerializer(serializers.Serializer):
    provider = serializers.CharField()
    access_token = serializers.CharField()
    
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'name', 'email', 'phone_number', 'gender', 'social_provider')
