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

import os
import sys
from pathlib import Path

# Add the parent directory to the path so we can import from getwvkeys
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask

from getwvkeys import config
from getwvkeys.config import SQLALCHEMY_DATABASE_URI
from getwvkeys.libraries import Library
from getwvkeys.models.PRD import PRD
from getwvkeys.models.Shared import db
from getwvkeys.models.User import User
from getwvkeys.models.WVD import WVD
from getwvkeys.user import FlaskUser


def create_app():
    """Create a minimal Flask app for database operations"""
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    return app


def create_system_user():
    """Create the system user"""
    app = create_app()
    with app.app_context():
        try:
            system_user = FlaskUser.create_system_user(db)
            print(f"Created system user: {system_user.username} (ID: {system_user.id})")
            return system_user
        except Exception as e:
            print(f"Error creating system user: {e}")
            return None


def get_system_user():
    """Get the system user (create if doesn't exist)"""
    app = create_app()
    with app.app_context():
        try:
            system_user = FlaskUser.get_system_user(db)
            print(f"System user found: {system_user.username} (ID: {system_user.id})")
            return system_user
        except Exception as e:
            print(f"Error getting system user: {e}")
            return None


def list_devices():
    """List all devices in the database"""
    app = create_app()
    with app.app_context():
        try:
            wvds = WVD.query.all()
            prds = PRD.query.all()

            print(f"\nWVD Devices ({len(wvds)} total):")
            for wvd in wvds:
                owner = User.query.filter_by(id=wvd.uploaded_by).first()
                owner_name = owner.username if owner else "Unknown"
                rotation_status = "✅" if wvd.enabled_for_rotation else "❌"
                print(
                    f"  - ID: {wvd.id} | Hash: {wvd.hash} | Owner: {owner_name} ({wvd.uploaded_by}) | Rotation: {rotation_status}"
                )

            print(f"\nPRD Devices ({len(prds)} total):")
            for prd in prds:
                owner = User.query.filter_by(id=prd.uploaded_by).first()
                owner_name = owner.username if owner else "Unknown"
                rotation_status = "✅" if prd.enabled_for_rotation else "❌"
                print(
                    f"  - ID: {prd.id} | Hash: {prd.hash} | Owner: {owner_name} ({prd.uploaded_by}) | Rotation: {rotation_status}"
                )

        except Exception as e:
            print(f"Error listing devices: {e}")


def migrate_devices_to_system(device_hashes, device_type):
    """Migrate specific devices to system user"""
    app = create_app()
    with app.app_context():
        try:
            library = Library(db)
            library.migrate_devices_to_system(device_hashes, device_type)
            print(f"Successfully migrated {len(device_hashes)} {device_type.upper()} devices to system user")
        except Exception as e:
            print(f"Error migrating devices: {e}")


def show_system_devices():
    """Show devices owned by the system user"""
    app = create_app()
    with app.app_context():
        library = Library(db)
        devices = library.get_system_devices()
        wvds, prds = library.get_rotation_devices()

        print(f"\nSystem User Devices:")
        print(f"  WVDs: {len(devices['wvds'])}")
        for wvd in devices["wvds"]:
            rotation_status = "ENABLED" if any(r == wvd["hash"] for r in wvds) else "DISABLED"
            print(f"    - ID: {wvd['id']} | Hash: {wvd['hash']} | Rotation: {rotation_status}")

        print(f"  PRDs: {len(devices['prds'])}")
        for prd in devices["prds"]:
            rotation_status = "ENABLED" if any(r == prd["hash"] for r in prds) else "DISABLED"
            print(f"    - ID: {prd['id']} | Hash: {prd['hash']} | Rotation: {rotation_status}")


def set_device_rotation(device_id, device_type, enabled):
    """Enable or disable device rotation"""
    app = create_app()
    with app.app_context():
        try:
            library = Library(db)
            device = library.set_device_rotation_status(device_id, device_type, enabled)
            status = "enabled" if enabled else "disabled"
            print(f"{device_type.upper()} device {device_id} rotation {status}")

            # Rebuild config cache
            library.build_rotation_config_cache()
            print("Rotation configuration cache refreshed")

        except Exception as e:
            print(f"Error setting device rotation: {e}")


def show_rotation_devices():
    """Show only devices enabled for rotation"""
    app = create_app()
    with app.app_context():
        library = Library(db)
        wvds, prds = library.get_rotation_devices()

        print(f"\nDevices Enabled for Rotation:")
        print(f"  WVDs: {len(wvds)}")
        for wvd in wvds:
            print(f"    - ID: {wvd['id']} | Hash: {wvd['hash']}")

        print(f"  PRDs: {len(prds)}")
        for prd in prds:
            print(f"    - ID: {prd['id']} | Hash: {prd['hash']}")


def main():
    if len(sys.argv) < 2:
        print(
            """
System User Management Utility

Usage:
  python manage_system_user.py <command> [args...]

Commands:
  create                        - Create the system user
  info                          - Show system user information
  list-devices                  - List all devices in the database
  show-system-devices           - Show devices owned by the system user
  show-rotation-devices         - Show devices enabled for rotation
  migrate-wvd <hash1,hash2>     - Migrate WVD devices to system user
  migrate-prd <hash1,hash2>     - Migrate PRD devices to system user
  enable-rotation-wvd <id>      - Enable WVD device for rotation
  disable-rotation-wvd <id>     - Disable WVD device for rotation
  enable-rotation-prd <id>      - Enable PRD device for rotation
  disable-rotation-prd <id>     - Disable PRD device for rotation

Examples:
  python manage_system_user.py create
  python manage_system_user.py list-devices
  python manage_system_user.py migrate-wvd abc123,def456
  python manage_system_user.py enable-rotation-wvd 5
  python manage_system_user.py show-rotation-devices
"""
        )
        return

    command = sys.argv[1].lower()

    if command == "create":
        create_system_user()

    elif command == "info":
        get_system_user()
        show_system_devices()

    elif command == "list-devices":
        list_devices()

    elif command == "show-system-devices":
        show_system_devices()

    elif command == "show-rotation-devices":
        show_rotation_devices()

    elif command == "migrate-wvd":
        if len(sys.argv) < 3:
            print("Please provide device hashes: migrate-wvd <hash1,hash2,hash3>")
            return

        hashes = [h.strip() for h in sys.argv[2].split(",")]
        migrate_devices_to_system(hashes, "wvd")

    elif command == "migrate-prd":
        if len(sys.argv) < 3:
            print("Please provide device hashes: migrate-prd <hash1,hash2,hash3>")
            return

        hashes = [h.strip() for h in sys.argv[2].split(",")]
        migrate_devices_to_system(hashes, "prd")

    elif command == "enable-rotation-wvd":
        if len(sys.argv) < 3:
            print("Please provide device ID: enable-rotation-wvd <device_id>")
            return

        device_id = int(sys.argv[2])
        set_device_rotation(device_id, "wvd", True)

    elif command == "disable-rotation-wvd":
        if len(sys.argv) < 3:
            print("Please provide device ID: disable-rotation-wvd <device_id>")
            return

        device_id = int(sys.argv[2])
        set_device_rotation(device_id, "wvd", False)

    elif command == "enable-rotation-prd":
        if len(sys.argv) < 3:
            print("Please provide device ID: enable-rotation-prd <device_id>")
            return

        device_id = int(sys.argv[2])
        set_device_rotation(device_id, "prd", True)

    elif command == "disable-rotation-prd":
        if len(sys.argv) < 3:
            print("Please provide device ID: disable-rotation-prd <device_id>")
            return

        device_id = int(sys.argv[2])
        set_device_rotation(device_id, "prd", False)

    else:
        print(f"Unknown command: {command}")
        print("Use 'python manage_system_user.py' to see available commands")


if __name__ == "__main__":
    main()
