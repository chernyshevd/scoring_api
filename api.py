#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import datetime
import logging
import hashlib
import uuid
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from scoring import get_interests, get_score
from store import Store

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import hashlib
import json
import logging
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from optparse import OptionParser
from typing import Optional

from scoring import get_interests, get_score
from store import Store

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class BaseField:
    def __init__(self, required: Optional[bool] = False, nullable: Optional[bool] = False) -> None:
        if not required and not nullable:
            raise ValueError("Optional field must be nullable")
        self.required = required
        self.nullable = nullable

    def validate(self, value):
        if self.required and value is None:
            raise ValueError(f'The field {type(self).__name__} is required')
        if not self.nullable and value in ('', [], (), {}):
            raise ValueError('The field should not be empty')
        return value


class CharField(BaseField):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, str):
            raise ValueError('The field should be string')
        return value


class ArgumentsField(BaseField):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, dict):
            raise ValueError('The field should be dict')
        return value


class EmailField(CharField):
    def validate(self, value):
        super().validate(value)
        if '@' not in value:
            raise ValueError('The field should be valid email')
        return value


class PhoneField(BaseField):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, (int, str)):
            raise ValueError('The field should be string or integer')
        if not str(value)[0] == '7' or not len(str(value)) == 11:
            raise ValueError('The field should start with 7 and has length 11')
        return value


class DateField(CharField):
    def validate(self, value):
        super().validate(value)
        try:
            datetime.datetime.strptime(value, '%d.%m.%Y')
        except ValueError:
            raise ValueError('The field should be date with DD.MM.YYYY format')
        return value


class BirthDayField(DateField):
    MAX_AGE = 70
    def validate(self, value):
        super().validate(value)
        birthday = datetime.datetime.strptime(value, '%d.%m.%Y')
        if datetime.datetime.now() - birthday > datetime.timedelta(days=self.MAX_AGE*365):
            raise ValueError(f'The age should not exceed {self.MAX_AGE} years')
        return value


class GenderField(BaseField):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, int) or value not in GENDERS:
            raise ValueError('The field should be integer 0, 1 or 2')
        return value


class ClientIDsField(BaseField):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, list):
            raise ValueError('The field should be list')
        for item in value:
            if not isinstance(item, int):
                raise ValueError('The field should be list of integers')
        return value


class MetaRequest(type):
    def __new__(cls, name, bases, attrs):
        fields = {}
        for key, value in attrs.items():
            if isinstance(value, BaseField):
                fields[key] = value
        attrs['_fields'] = fields
        return type.__new__(cls, name, bases, attrs)


class BaseRequest(metaclass=MetaRequest):
    def __init__(self, **kwargs):
        for attribute in self._fields:
            value = kwargs.get(attribute)
            setattr(self, attribute, value)

    def validate(self):
        for attribute, field in self._fields.items():
            value = getattr(self, attribute)
            if value is not None or field.required:
                field.validate(value)


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class ClientsInterestsRequest(MethodRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(MethodRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    @property
    def enough_fields(self):
        if (
                (self.phone and self.email) or
                (self.first_name and self.last_name) or
                (self.birthday and self.gender in GENDERS)
        ):
            return True
        else:
            return False


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode('utf-8')).hexdigest()
    return digest == request.token


def clients_interests_handler(request, ctx, store):
    try:
        response = ClientsInterestsRequest(**request.arguments)
        response.validate()
    except ValueError as err:
        return {
            'code': INVALID_REQUEST,
            'error': str(err)
        }, INVALID_REQUEST

    clients_interests = {}

    for client_id in response.client_ids:
        clients_interests[f'client_id{client_id}'] = get_interests(store, client_id)
    ctx['nclients'] = len(response.client_ids)
    code = OK
    return clients_interests, code


def online_score_handler(request, ctx, store):
    if request.is_admin:
        score = 42
        return {'score': score}, OK
    try:
        response = OnlineScoreRequest(**request.arguments)
        response.validate()
    except ValueError as err:
        return {
            'code': INVALID_REQUEST,
            'error': str(err)
        }, INVALID_REQUEST

    if not response.enough_fields:
        return {
           'code': INVALID_REQUEST,
           'error': 'INVALID_REQUEST: not enough fields'
        }, INVALID_REQUEST

    score = get_score(
        store=store,
        phone=response.phone,
        email=response.email,
        birthday=response.birthday,
        gender=response.gender,
        first_name=response.first_name,
        last_name=response.last_name
    )
    code = OK

    ctx['has'] = [field_name for field_name in response._fields if getattr(response, field_name) is not None]

    return {'score': score}, code


def method_handler(request, ctx, store):
    method = {'clients_interests': clients_interests_handler,
              'online_score': online_score_handler}
    try:
        response = MethodRequest(**request.get('body'))
        response.validate()
    except ValueError as err:
        return {
            'code': INVALID_REQUEST,
            'error': str(err)
        }, INVALID_REQUEST

    if not response.method:
        return {
            'code': INVALID_REQUEST,
            'error': 'INVALID_REQUEST'
        }, INVALID_REQUEST

    if not check_auth(response):
        return None, FORBIDDEN

    response, code = method[response.method](response, ctx, store)
    return response, code


class StoringHTTPServer(HTTPServer):
    def __init__(self, *args, storage_address=('localhost', 6379), **kwargs):
        self.store = Store(storage_address[0], storage_address[1])
        super(StoringHTTPServer, self).__init__(*args, **kwargs)

    def server_activate(self):
        self.store.connect()
        super(StoringHTTPServer, self).server_activate()

    def server_close(self):
        super(StoringHTTPServer, self).server_close()
        self.store.disconnect()


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    # store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:  # noqa E722
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info('%s: %s %s' % (
                self.path,
                data_string.decode('utf8'),
                context["request_id"])
            )
            if path in self.router:
                try:
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers},
                        context,
                        self.server.store
                    )
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {
                "error": response or ERRORS.get(code, "Unknown Error"),
                "code": code
            }
        context.update(r)
        logging.info(str(context))
        self.wfile.write(json.dumps(r).encode())
        return



if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    parser.add_argument("--storage-host", action="store", default="localhost")
    parser.add_argument("--storage-port", action="store", type=int, default=6379)
    args = parser.parse_args()
    logging.basicConfig(filename=args.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = StoringHTTPServer(("localhost", args.port), MainHTTPHandler,
                               storage_address=(args.storage_host, args.storage_port))
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
