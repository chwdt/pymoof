from unittest import mock

import pytest

from pymoof.clients.sx3 import BellTone
from pymoof.clients.sx3 import LockState
from pymoof.clients.sx3 import Sound
from pymoof.clients.sx3 import SX3Client

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes

@pytest.fixture
def key():
    return "a" * 32


@pytest.fixture
def user_key_id():
    return 1


@pytest.fixture
def bleak_client(services):
    mock_client = mock.AsyncMock()
    mock_client.get_services.return_value = services
    return mock_client


@pytest.fixture
def services(service):
    services = mock.Mock()
    services.get_service.return_value = service
    return services


@pytest.fixture
def service():
    return mock.Mock()


@pytest.fixture
def client(bleak_client, key, user_key_id):
    return SX3Client(bleak_client, key, user_key_id)


def encrypt(key, data):
    payload = bytearray(data)
    while len(payload) % 16 != 0:
        payload.append(0)
    cipher = Cipher(algorithms.AES(bytes.fromhex(key)), modes.ECB())
    encryptor = cipher.encryptor()
    payload = bytes(encryptor.update(payload) + encryptor.finalize())
    return payload


@pytest.mark.asyncio
async def test_authenticate(key, bleak_client, client, services, service):
    bleak_client.read_gatt_char.return_value = b"ab"
    await client.authenticate()
    data = encrypt(key, b"ab") + b'\x00\x00\x00\x01'
    bleak_client.write_gatt_char.assert_called_once_with(bleak_client.write_gatt_char.call_args.args[0], data, response=True)


# Smoke tests
@pytest.mark.asyncio
async def test_set_bell_tone(key, bleak_client, client):
    bleak_client.read_gatt_char.return_value = b"ab"
    await client.set_bell_tone(BellTone.PARTY)
    data = encrypt(key, b"ab" + BellTone.PARTY.value.to_bytes(1))
    bleak_client.write_gatt_char.assert_called_once_with(bleak_client.write_gatt_char.call_args.args[0], data, response=True)


@pytest.mark.asyncio
async def test_set_lock_state(key, bleak_client, client):
    bleak_client.read_gatt_char.return_value = b"ab"
    await client.set_lock_state(LockState.UNLOCKED)
    data = encrypt(key, b"ab" + LockState.UNLOCKED.value.to_bytes(1))
    bleak_client.write_gatt_char.assert_called_once_with(bleak_client.write_gatt_char.call_args.args[0], data, response=True)


@pytest.mark.asyncio
async def test_set_power_level(key, bleak_client, client):
    bleak_client.read_gatt_char.return_value = b"ab"
    await client.set_power_level(0)
    data = encrypt(key, b"ab" + (0).to_bytes(1) + b'\x01')
    bleak_client.write_gatt_char.assert_called_once_with(bleak_client.write_gatt_char.call_args.args[0], data, response=True)


@pytest.mark.asyncio
async def test_play_sound(key, bleak_client, client):
    bleak_client.read_gatt_char.return_value = b"ab"
    await client.play_sound(Sound.SCROLLING_TONE, 1)
    data = encrypt(key, b"ab" + (Sound.SCROLLING_TONE).value.to_bytes(1) + (1).to_bytes(1))
    bleak_client.write_gatt_char.assert_called_once_with(bleak_client.write_gatt_char.call_args.args[0], data, response=True)


@pytest.mark.asyncio
async def test_get_battery_level(key, bleak_client, client):
    bleak_client.read_gatt_char.return_value = encrypt(key, (67).to_bytes(1))
    assert await client.get_battery_level() == 67


@pytest.mark.asyncio
async def test_get_distance_travelled(key, bleak_client, client):
    bleak_client.read_gatt_char.return_value = encrypt(key, (12345678).to_bytes(4, 'little'))
    assert await client.get_distance_travelled() == 1234567.8


@pytest.mark.asyncio
async def test_get_power_level(key, bleak_client, client):
    bleak_client.read_gatt_char.return_value = encrypt(key, (3).to_bytes(1))
    assert await client.get_power_level() == 3
    assert await client.get_distance_travelled() == 0.3


@pytest.mark.asyncio
async def test_frame_number(key, bleak_client, client):
    bleak_client.read_gatt_char.return_value = b'ASY-123456'
    assert await client.get_frame_number() == 'ASY-123456'


@pytest.mark.asyncio
async def test_sound_volume(key, bleak_client, client):
    bleak_client.read_gatt_char.return_value = encrypt(key, (80).to_bytes(1))
    assert await client.get_sound_volume() == 80


@pytest.mark.asyncio
async def test_get_speed(key, bleak_client, client):
    bleak_client.read_gatt_char.return_value = encrypt(key, (25).to_bytes(1))
    assert await client.get_speed() == 25
