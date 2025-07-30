import asyncio
from bleak import BleakScanner

direccion_celular = "88:40:3b:7e:2c:bd"
direccion_objetivo = "f4:12:fa:88:20:ce"

async def escanear_dispositivos():
    print("🔍 Escaneando durante 20 segundos...\n")
    devices = await BleakScanner.discover(timeout=20.0)

    for device in devices:
        addr = device.address.lower()
        if addr in (direccion_celular, direccion_objetivo):
            # Intentamos obtener RSSI desde distintas ubicaciones
            rssi = getattr(device, "rssi", "N/D")
            if rssi == "N/D" and hasattr(device, "details"):
                rssi = getattr(device.details, "rssi", "N/D")
                
            print(f"📡 Encontrado: {device.address}  |  RSSI: {rssi} dB")
            print(f"   🔹 Nombre: {device.name or 'No disponible'}")
            print("-" * 40)

asyncio.run(escanear_dispositivos())

