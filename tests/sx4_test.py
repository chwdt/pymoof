from unittest import mock

import pytest

from pymoof.clients.sx4 import BellTone
from pymoof.clients.sx4 import LockState
from pymoof.clients.sx4 import Sound
from pymoof.clients.sx4 import SX4Client

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes

@pytest.fixture(scope='module')
def key():
    return 'a' * 32


@pytest.fixture(scope='module')
def nonce():
    return b'abcdefghijklmnop'


@pytest.fixture(scope='module')
def user_key_id():
    return 1


@pytest.fixture(scope='module')
def bleak_client(services):
    mock_client = mock.AsyncMock()
    mock_client.get_services.return_value = services
    return mock_client


@pytest.fixture(scope='module')
def services(service):
    services = mock.Mock()
    services.get_service.return_value = service
    return services


@pytest.fixture(scope='module')
def service():
    return mock.Mock()


@pytest.fixture(scope='module')
def client(bleak_client, key, user_key_id):
    return SX4Client(bleak_client, key, user_key_id)


class crypto_state:
    def __init__(self, key, nonce):
        self._key = key
        self._nonce = nonce
        self._iv_read = bytes(255 - x for x in nonce)
        self._iv_write = bytes(16)

    def wencrypt(self, data):
        payload = bytearray(data)
        while len(payload) % 16 != 0:
            payload.append(0)
        cipher = Cipher(algorithms.AES(bytes.fromhex(self._key)), modes.CBC(self._iv_write))
        encryptor = cipher.encryptor()
        payload = bytes(encryptor.update(payload) + encryptor.finalize())
        self._iv_write = payload[:16]
        return payload

    def rencrypt(self, data):
        payload = bytearray(data)
        while len(payload) % 16 != 0:
            payload.append(0)
        cipher = Cipher(algorithms.AES(bytes.fromhex(self._key)), modes.CBC(self._iv_read))
        encryptor = cipher.encryptor()
        payload = bytes(encryptor.update(payload) + encryptor.finalize())
        return payload


@pytest.fixture(scope='module')
def crypto(key, nonce):
     return crypto_state(key, nonce)


@pytest.mark.asyncio
async def test_authenticate(crypto, nonce, bleak_client, client, services, service):
    bleak_client.read_gatt_char.return_value = crypto._nonce
    await client.authenticate()
    data = crypto.wencrypt(crypto._nonce) + b'\x00\x00\x00\x01'
    bleak_client.write_gatt_char.assert_called_once_with(bleak_client.write_gatt_char.call_args.args[0], data, response=True)


# Smoke tests
@pytest.mark.asyncio
async def test_set_bell_tone(crypto, bleak_client, client):
    bleak_client.reset_mock()
    await client.set_bell_tone(BellTone.PARTY)
    data = crypto.wencrypt(b'\x70\x01\x17')
    bleak_client.write_gatt_char.assert_called_once_with(bleak_client.write_gatt_char.call_args.args[0], data, response=True)


@pytest.mark.asyncio
async def test_set_lock_state(crypto, bleak_client, client):
    bleak_client.reset_mock()
    await client.set_lock_state(LockState.UNLOCKED)
    data = crypto.wencrypt(b'\x15\x01\x00')
    bleak_client.write_gatt_char.assert_called_once_with(bleak_client.write_gatt_char.call_args.args[0], data, response=True)


@pytest.mark.asyncio
async def test_set_power_level(crypto, bleak_client, client):
    bleak_client.reset_mock()
    await client.set_power_level(0)
    data = crypto.wencrypt(b'\xd6\x02\x00\x00')
    bleak_client.write_gatt_char.assert_called_once_with(bleak_client.write_gatt_char.call_args.args[0], data, response=True)


@pytest.mark.asyncio
async def test_play_sound(crypto, bleak_client, client):
    bleak_client.reset_mock()
    await client.play_sound(Sound.SCROLLING_TONE, 1)
    data = crypto.wencrypt(b'\xc4\x02\x01\x01')
    bleak_client.write_gatt_char.assert_called_once_with(bleak_client.write_gatt_char.call_args.args[0], data, response=True)


@pytest.mark.asyncio
async def test_get_battery_level(crypto, bleak_client, client):
    bleak_client.read_gatt_char.return_value = crypto.rencrypt((67).to_bytes(1))
    assert await client.get_battery_level() == 67


@pytest.mark.asyncio
async def test_get_distance_travelled(crypto, bleak_client, client):
    bleak_client.read_gatt_char.return_value = crypto.rencrypt((12345678).to_bytes(4, 'little'))
    assert await client.get_distance_travelled() == 1234567.8


@pytest.mark.asyncio
async def test_get_power_level(crypto, bleak_client, client):
    bleak_client.read_gatt_char.return_value = crypto.rencrypt((3).to_bytes(1))
    assert await client.get_power_level() == 3
    assert await client.get_distance_travelled() == 0.3


@pytest.mark.asyncio
async def test_sound_volume(crypto, bleak_client, client):
    bleak_client.read_gatt_char.return_value = crypto.rencrypt((80).to_bytes(1))
    assert await client.get_sound_volume() == 80


@pytest.mark.asyncio
async def test_get_speed(crypto, bleak_client, client):
    bleak_client.read_gatt_char.return_value = crypto.rencrypt((25).to_bytes(1))
    assert await client.get_speed() == 25
