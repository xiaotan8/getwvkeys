"""
This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
Copyright (C) 2022-2024 Notaghost, Puyodead1 and GetWVKeys contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
This script was created to aid in database migration by exporting system device keys for conversion
"""

import base64
import json
from pathlib import Path

import mariadb

mydb = mariadb.connect(host="localhost", user="getwvkeys", password="", database="getwvkeys_old")


cursor = mydb.cursor()

query = "SELECT client_id_blob_filename, device_private_key FROM cdms WHERE code = %s"


system_devices = []


export_root = Path("devices")
manifest_path = export_root / "manifest.json"

manifest_tmp = []

for device in system_devices:
    cursor.execute(query, (device,))
    result = cursor.fetchone()
    if result is None:
        print(f"Device {device} not found")
    else:
        print(f"Device {device} found")
        client_id = result[0]
        private_key = result[1]

        code_safe = device.replace("/", "_").replace(":", "_").replace(".", "_").replace(" ", "_").replace("-", "_")

        client_id_filename = code_safe + "_device_client_id"
        private_key_filename = code_safe + "_device_private_key"

        client_id_path = export_root / client_id_filename
        private_key_path = export_root / private_key_filename

        with open(client_id_path, "wb") as f:
            f.write(base64.b64decode(client_id))

        with open(private_key_path, "wb") as f:
            f.write(base64.b64decode(private_key))

        manifest_tmp.append([client_id_filename, private_key_filename])

print(f"Found {len(manifest_tmp)}/{len(system_devices)} devices")

print("Writing manifest...")

with open(manifest_path, "w") as f:
    f.write(json.dumps(manifest_tmp))


print("Done")
