import enum
import math

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes


class SX4Profile:
    """
    Represents the profile for the GATT UUIDs for the S4/X4. Also contains functionality
    to encrypt and decrypt BLE payloads, as well as building the authentication payload.

    :param key: The hexidecimal string of the encrypted key from Vanmoof servers.
    :param user_key_id: Int of the user key id from Vanmoof servers.
    """

    def __init__(self, key: str, user_key_id: int) -> None:
        self._key = key
        self._user_key_id = user_key_id
        self._iv_read = bytes(16)
        self._iv_write = bytes(16)

    def crc8(self, data):
        TABLE = [
            0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15,   0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
            0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65,   0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,
            0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5,   0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
            0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85,   0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,
            0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2,   0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA,
            0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2,   0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A,
            0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32,   0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A,
            0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42,   0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A,
            0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C,   0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4,
            0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC,   0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4,
            0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C,   0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44,
            0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C,   0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34,
            0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B,   0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63,
            0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B,   0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13,
            0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB,   0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83,
            0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB,   0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3
        ]

        crc = 0x00
        for b in data:
            crc = TABLE[crc ^ b];
        return crc

    def build_authentication_payload(self, nonce: bytes) -> bytes:
        """
        Builds the authentication payload given a nonce.

        :param nonce: A bytes array that represents the nonce from a challenge response.
        """
        cipher = Cipher(algorithms.AES(bytes.fromhex(self._key)), modes.CBC(self._iv_read))
        encryptor = cipher.encryptor()

        data = bytearray(16)
        data[0:16] = nonce
        data = bytearray(encryptor.update(data) + encryptor.finalize())

        self._iv_read = bytes(255 - x for x in nonce)
        self._iv_write = data[:16]

        # Append the user key id
        data.extend([0, 0, 0, self._user_key_id])

        return bytes(data)

    def decrypt_payload(self, data: bytes) -> bytes:
        """
        Decrypts a bluetooth payload.

        :param data: A bytes array of data. Must be a multiple of 16 bytes long.
        """
        cipher = Cipher(algorithms.AES(bytes.fromhex(self._key)), modes.CBC(self._iv_read))
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def build_encrypted_payload(self, data: bytes) -> bytes:
        """
        Encrypts data signed with a nonce. This will build a payload and pad with
        zeroes to the nearest multiple of 16 bytes.

        :param nonce: A bytes array that represents the nonce from a challenge response.
        :param data: A bytes array of data.
        """
        cipher = Cipher(algorithms.AES(bytes.fromhex(self._key)), modes.CBC(self._iv_write))
        encryptor = cipher.encryptor()

        payload = bytearray(16)
        payload[2:] = data
        payload[1] = len(data)
        payload[0] = self.crc8(payload[1:])

        # Pad to the nearest cipher 16 byte block size
        for _ in range(math.ceil(len(payload) / 16) * 16 - len(payload)):
            payload.append(0)

        payload = bytes(encryptor.update(payload) + encryptor.finalize())

        self._iv_write = payload[-16:]

        return payload

    class Security(enum.Enum):

        SERVICE_UUID = "278d5500-4692-039f-3445-a23fc55333d0"

        CHALLENGE = "278d5501-4692-039f-3445-a23fc55333d0"
        KEY_INDEX = "278d5502-4692-039f-3445-a23fc55333d0"
        BACKUP_CODE = "278d5503-4692-039f-3445-a23fc55333d0"
        BIKE_MESSAGE = "278d5505-4692-039f-3445-a23fc55333d0"

    class Defense(enum.Enum):

        SERVICE_UUID = "278d5520-4692-039f-3445-a23fc55333d0"

        LOCK_STATE = "278d5521-4692-039f-3445-a23fc55333d0"
        UNLOCK_REQUEST = "278d5522-4692-039f-3445-a23fc55333d0"
        ALARM_STATE = "278d5523-4692-039f-3445-a23fc55333d0"
        ALARM_MODE = "278d5524-4692-039f-3445-a23fc55333d0"

    class Movement(enum.Enum):

        SERVICE_UUID = "278d5530-4692-039f-3445-a23fc55333d0"

        DISTANCE = "278d5531-4692-039f-3445-a23fc55333d0"
        SPEED = "278d5532-4692-039f-3445-a23fc55333d0"
        UNIT_SYSTEM = "278d5533-4692-039f-3445-a23fc55333d0"
        POWER_LEVEL = "278d5534-4692-039f-3445-a23fc55333d0"
        SPEED_LIMIT = "278d5535-4692-039f-3445-a23fc55333d0"
        E_SHIFTER_GEAR = "278d5536-4692-039f-3445-a23fc55333d0"
        E_SHIFTIG_POINTS = "278d5537-4692-039f-3445-a23fc55333d0"
        E_SHIFTER_MODE = "278d5538-4692-039f-3445-a23fc55333d0"

    class BikeInfo(enum.Enum):

        SERVICE_UUID = "278d5540-4692-039f-3445-a23fc55333d0"

        MOTOR_BATTERY_LEVEL = "278d5541-4692-039f-3445-a23fc55333d0"
        MOTOR_BATTERY_STATE = "278d5542-4692-039f-3445-a23fc55333d0"
        MODULE_BATTERY_LEVEL = "278d5543-4692-039f-3445-a23fc55333d0"
        MODULE_BATTERY_STATE = "278d5544-4692-039f-3445-a23fc55333d0"
        BIKE_FIRMWARE_VERSION = "278d554a-4692-039f-3445-a23fc55333d0"
        BLE_CHIP_FIRMWARE_VERSION = "278d554b-4692-039f-3445-a23fc55333d0"
        CONTROLLER_FIRMWARE_VERSION = "278d554c-4692-039f-3445-a23fc55333d0"
        PCBA_HARDWARE_VERSION = "278d554d-4692-039f-3445-a23fc55333d0"
        GSM_FIRMWARE_VERSION = "278d554e-4692-039f-3445-a23fc55333d0"
        E_SHIFTER_FIRMWARE_VERSION = "278d554f-4692-039f-3445-a23fc55333d0"
        BATTERY_FIRMWARE_VERSION = "278d5550-4692-039f-3445-a23fc55333d0"

        # data returned seems to be firmware version info?
        _UNKNOWN = "278d5551-4692-039f-3445-a23fc55333d0"

        FRAME_NUMBER = "278d5552-4692-039f-3445-a23fc55333d0"

    class BikeState(enum.Enum):

        SERVICE_UUID = "278d5560-4692-039f-3445-a23fc55333d0"

        MODULE_MODE = "278d5561-4692-039f-3445-a23fc55333d0"
        MODULE_STATE = "278d5562-4692-039f-3445-a23fc55333d0"
        ERRORS = "278d5563-4692-039f-3445-a23fc55333d0"
        WHEEL_SIZE = "278d5564-4692-039f-3445-a23fc55333d0"
        CLOCK = "278d5567-4692-039f-3445-a23fc55333d0"
        BUTTON_STATES = "278d5568-4692-039f-3445-a23fc55333d0"

    class Sound(enum.Enum):

        SERVICE_UUID = "278d5570-4692-039f-3445-a23fc55333d0"

        PLAY_SOUND = "278d5571-4692-039f-3445-a23fc55333d0"
        SOUND_VOLUME = "278d5572-4692-039f-3445-a23fc55333d0"
        BELL_SOUND = "278d5574-4692-039f-3445-a23fc55333d0"

    class Light(enum.Enum):

        SERVICE_UUID = "278d5580-4692-039f-3445-a23fc55333d0"

        LIGHT_MODE = "278d5581-4692-039f-3445-a23fc55333d0"
        LIGHT_STATE = "278d5582-4692-039f-3445-a23fc55333d0"
        SENSOR = "278d5584-4692-039f-3445-a23fc55333d0"

    class Maintenance(enum.Enum):

        SERVICE_UUID = "278d55c0-4692-039f-3445-a23fc55333d0"

        LOG_MODE = "278d55c1-4692-039f-3445-a23fc55333d0"
        LOG_SIZE = "278d55c2-4692-039f-3445-a23fc55333d0"
        LOG_BLOCK = "278d55c3-4692-039f-3445-a23fc55333d0"
