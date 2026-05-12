import asyncio

from bleak import BleakScanner


async def query():
    devices = await BleakScanner.discover(
        service_uuids=[
            "6acc5540-e631-4069-944d-b8ca7598ad50",
            "8e7f1a50-087a-44c9-b292-a2c628fdd9aa",
            "6acb5520-e631-4069-944d-b8ca7598ad50",
            "278d5540-4692-039f-3445-a23fc55333d0",
        ],
    )
    for device in devices:
        if "278d5540-4692-039f-3445-a23fc55333d0" in device.metadata["uuids"]:
            print("Found SX4:", device.address)
            return device
        if "6acc5540-e631-4069-944d-b8ca7598ad50" in device.metadata["uuids"]:
            print("Found SX3:", device.address)
            return device
        if "8e7f1a50-087a-44c9-b292-a2c628fdd9aa" in device.metadata["uuids"]:
            print("Found SX1/SX2:", device.address, "but it's not supported")
            raise Exception()
        if "6acb5520-e631-4069-944d-b8ca7598ad50" in device.metadata["uuids"]:
            print("Found Smart SX1:", device.address, "but it's not supported")
            raise Exception()
    print("No Vanmoof bikes found")


if __name__ == "__main__":
    asyncio.run(query())
