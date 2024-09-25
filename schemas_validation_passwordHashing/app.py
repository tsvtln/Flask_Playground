from datetime import datetime, timedelta
from enum import Enum
from typing import List

from decouple import config
from flask import Flask, request
from flask_migrate import Migrate
from flask_restful import Resource, Api, abort
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields, ValidationError, validate, validates
from password_strength import PasswordPolicy
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column
from werkzeug.exceptions import Forbidden
from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPTokenAuth
import jwt

app = Flask(__name__)
api = Api(app)

db_user = config("DB_USER")
db_password = config("DB_PASSWORD")

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_password}@localhost:5432/clothes'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

auth = HTTPTokenAuth(scheme='Bearer')


class UserRolesEnum(Enum):
    admin = 'admin',
    user = 'user',
    super_admin = 'super_admin'


@auth.verify_token
def verify_token(token):
    try:
        user = User.decode_token(token)
        return user
    except jwt.exceptions.InvalidTokenError as ex:
        abort(401)


def permission_required(permission: List[UserRolesEnum]):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            # if not isinstance(permission, list):
            #     requierd_permission = [permission]
            user = auth.current_user()
            if user.role != permission:
                raise Forbidden()
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def validate_schema(schema):
    def decorator(function):
        def decorated_function(*args, **kwargs):
            schema_obj = schema()
            data = request.get_json()
            errors = schema_obj.validate(data)
            if errors:
                raise ValidationError(errors)
            return function(*args, **kwargs)

        return decorated_function

    return decorator


class User(db.Model):
    __tablename__ = 'user'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(db.String(120), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(db.String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(db.String(255), nullable=False)
    created_on: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_on: Mapped[datetime] = mapped_column(onupdate=func.now(), server_default=func.now())
    role: Mapped[UserRolesEnum] = mapped_column(
        db.Enum(UserRolesEnum),
        default=UserRolesEnum.user,
        nullable=False
    )

    def encode_token(self):
        key = config("SECRET_KEY")
        data = {
            "exp": datetime.utcnow() + timedelta(days=2),
            "sub": self.id
        }
        return jwt.encode(data, key, algorithm="HS256")

    @staticmethod
    def decode_token(token):
        key = config("SECRET_KEY")
        data = jwt.decode(token, key, algorithms=["HS256"])
        user_id = data["sub"]
        user = db.session.execute(db.select(User).filter_by(id=user_id)).scalar()
        if not user:
            raise jwt.exceptions.InvalidTokenError()
        return user


class CoffeeEnum(Enum):
    weak = "This coffee type is weak and can be taken even in the evenings"
    strong = "This coffee is only recommended to be used in the mornings. Very strong"


class SizeEnum(Enum):
    xs = "xs"
    s = "s"
    m = "m"
    l = "l"
    xl = "xl"
    xxl = "xxl"


class ColorEnum(Enum):
    pink = "pink"
    black = "black"
    white = "white"
    yellow = "yellow"


class Clothes(db.Model):
    __tablename__ = 'clothes'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(db.String(255), nullable=False)
    size: Mapped[SizeEnum] = mapped_column(
        db.Enum(SizeEnum),
        default=SizeEnum.s,
        nullable=False
    )
    color: Mapped[ColorEnum] = mapped_column(
        db.Enum(ColorEnum),
        default=ColorEnum.white,
        nullable=False
    )
    photo: Mapped[str] = mapped_column(db.String(255), nullable=False)
    created_on: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_on: Mapped[datetime] = mapped_column(onupdate=func.now(), server_default=func.now())


policy = PasswordPolicy.from_names(
    uppercase=1,  # need min. 1 uppercase letters
    numbers=1,  # need min. 1 digits
    special=1,  # need min. 1 special characters
    nonletters=1,  # need min. 1 non-letter characters (digits, specials, anything)
)


def validate_password_strength(value):
    errors = policy.test(value)
    if errors:
        raise ValidationError("Password must have letters, numbers, digits and special characters")


# def validate_full_name(value):
#     try:
#         first_name, last_name = value.split()
#     except ValueError:
#         raise ValidationError("You should provide first and last name")
#
#     if len(first_name) < 2 or len(last_name) < 2:
#         raise ValidationError("Each name must contain at least two characters.")


class BaseUserSchema(Schema):
    email = fields.Email(required=True)
    full_name = fields.String(required=True,
                              # validate=validate.And(validate.Length(max=255),
                              #                       validate_full_name)
                              )

    @validates("full_name")
    def validate_full_name(self, value):
        try:
            first_name, last_name = value.split()
        except ValueError:
            raise ValidationError("You should provide first and last name")

        if len(first_name) < 2 or len(last_name) < 2:
            raise ValidationError("Each name must contain at least two characters.")


class UserSignInSchema(BaseUserSchema):
    password = fields.String(
        required=True,
        validate=validate.And(
            validate.Length(min=8, max=20),
            validate_password_strength
        )
    )


class UserResponseSchema(BaseUserSchema):
    id = fields.Integer()


class UsersResource(Resource):
    @validate_schema(UserSignInSchema)
    def post(self):
        data = request.get_json()

        schema = UserSignInSchema()
        errors = schema.validate(data)

        if not errors:
            data['password'] = generate_password_hash(data['password'], method='pbkdf2:sha256')
            user = User(**data)
            db.session.add(user)
            try:
                db.session.commit()
                # response_schema = UserResponseSchema()
                # response_data = response_schema.dump(user)
                # return response_data, 201
                token = user.encode_token()
                return {"token": token}, 201

            except IntegrityError as ex:
                return {"message": "Email already exists, please sign in instead"}, 400

        return errors, 400


class UserLoginResource(Resource):
    def post(self):
        data = request.get_json()
        # TODO create schema and validate
        user = db.session.execute(db.select(User).filter_by(email=data["email"])).scalar()
        if not user:
            raise Exception("Invalid email or pass")

        result = check_password_hash(user['password'], data["password"])
        if result:
            return {"token": user.encode_token()}
        raise Exception("Invalid mail or password")


class UserResource(Resource):
    @auth.login_required
    @permission_required([UserRolesEnum.admin, UserRolesEnum.super_admin])
    def get(self, pk):
        user = db.session.execute(db.select(User).filter_by(id=pk)).scalar()
        if not user:
            return {"message": "Not found"}, 404
        return UserResponseSchema().dump(user)


class AddressSchema(Schema):
    street = fields.String()
    city = fields.String()


class PersonInfoSchema(Schema):
    name = fields.String()
    address = fields.Nested(AddressSchema)


api.add_resource(UsersResource, "/register")
api.add_resource(UserResource, "/users/<int:pk>")
api.add_resource(UserLoginResource, "/login")
