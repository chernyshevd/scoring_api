import os
import sys
import pytest

CUR_PATH = os.path.dirname(__file__)
sys.path.append(os.path.join(CUR_PATH, '../..'))

import store


@pytest.fixture(scope="session", autouse=True)
def client():
    client = store.Store('localhost', 6379)
    client.connect()
    client.cache_connection.flushall()
    client.db_connection.flushall()
    yield client
    client.disconnect()


@pytest.mark.parametrize('key', ['key'])
def test_empty_value(client, key):
    val1 = client.cache_get(key)
    assert val1 is None
    val2 = client.get(key)
    assert val2 is None


@pytest.mark.parametrize('key', ['key'])
@pytest.mark.parametrize('value', [
    None,
    0, 1, -1, 0.0, 1.0, -1.0,
    '', 'bar',
    [], [1, 2, 3],
    {}, {'1': 1, '2': 2, '3': 3}
])
@pytest.mark.parametrize('ttl', [60])
def test_cache_connection(client, key, value, ttl):
    client.cache_set(key, value, ttl)
    val1 = client.cache_get(key)
    val2 = client.cache_get(key)
    assert val1 == val2 == value


@pytest.mark.parametrize('key', ['key'])
@pytest.mark.parametrize('value', [
    None,
    0, 1, -1, 0.0, 1.0, -1.0,
    '', 'bar',
    [], [1, 2, 3],
    {}, {'1': 1, '2': 2, '3': 3}
])
@pytest.mark.parametrize('ttl', [60])
def test_df_connection(client, key, value, ttl):
    client.cache_set(key, value, ttl)
    val1 = client.get(key)
    val2 = client.get(key)
    assert val1 == val2 == value
