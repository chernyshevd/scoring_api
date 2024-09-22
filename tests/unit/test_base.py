"""
Test basic functionality for fields and requests
"""
import os
import sys
import pytest

CUR_PATH = os.path.dirname(__file__)
sys.path.append(os.path.join(CUR_PATH, '../..'))

from api import BaseField, BaseRequest


@pytest.fixture
def build_base_request_class():
    def _build_base_request_class(required: bool, nullable: bool):
        class C(BaseRequest):
            foo = BaseField(required=required, nullable=nullable)
        return C

    return _build_base_request_class

def test_not_required_not_nullable(build_base_request_class):
    # optional field must be nullable, so this should fail on class creation stage
    with pytest.raises(ValueError):
        build_base_request_class(required=False, nullable=False)


class TestBaseFieldRequiredNotNullable:
    @staticmethod
    @pytest.fixture
    def RequestClass(build_base_request_class):
        return build_base_request_class(required=True, nullable=False)

    @staticmethod
    @pytest.fixture
    def ValidatedRequestClass(RequestClass):

        class C(RequestClass):
            def _validate(self):
                if not isinstance(self.foo, int):
                    raise ValueError("foo must be int")

        return C


    @pytest.mark.parametrize("request_value", [{'foo': 'foo'}, {'foo': 0}, {'foo': 42, 'bar': None}])
    def test_base_passes(self, RequestClass, request_value):
        c = RequestClass(**request_value)
        assert c.foo == request_value['foo']
    @pytest.mark.parametrize("request_value", [{}, {'foo': None}])
    def test_base_fails(self, RequestClass, request_value):
        with pytest.raises(ValueError):
            RequestClass(**request_value).validate()

    @pytest.mark.parametrize("request_value", [{'foo': 0}, {'foo': 42, 'bar': None}])
    def test_validated_passes(self, ValidatedRequestClass, request_value):
        c = ValidatedRequestClass(**request_value)
        assert c.foo == request_value['foo']


    @pytest.mark.parametrize("request_value", [{}, {'foo': None}, {'foo': 'foo'}])
    def test_validated_fails(self, ValidatedRequestClass, request_value):
        with pytest.raises(ValueError):
            ValidatedRequestClass(**request_value)._validate()
