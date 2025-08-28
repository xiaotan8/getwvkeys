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
                print(f"  - Hash: {wvd.hash} | Owner: {owner_name} ({wvd.uploaded_by})")

            print(f"\nPRD Devices ({len(prds)} total):")
            for prd in prds:
                owner = User.query.filter_by(id=prd.uploaded_by).first()
                owner_name = owner.username if owner else "Unknown"
                print(f"  - Hash: {prd.hash} | Owner: {owner_name} ({prd.uploaded_by})")

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
        try:
            library = Library(db)
            devices = library.get_system_devices()

            print(f"\nSystem User Devices:")
            print(f"  WVDs: {len(devices['wvds'])}")
            for wvd in devices["wvds"]:
                print(f"    - ID: {wvd['id']} | Hash: {wvd['hash'][:16]}...")

            print(f"  PRDs: {len(devices['prds'])}")
            for prd in devices["prds"]:
                print(f"    - ID: {prd['id']} | Hash: {prd['hash'][:16]}...")

        except Exception as e:
            print(f"Error showing system devices: {e}")


def main():
    if len(sys.argv) < 2:
        print(
            """
System User Management Utility

Usage:
  python manage_system_user.py <command> [args...]

Commands:
  create                     - Create the system user
  info                       - Show system user information
  list-devices              - List all devices in the database
  show-system-devices       - Show devices owned by the system user
  migrate-wvd <hash1,hash2> - Migrate WVD devices to system user
  migrate-prd <hash1,hash2> - Migrate PRD devices to system user

Examples:
  python manage_system_user.py create
  python manage_system_user.py list-devices
  python manage_system_user.py migrate-wvd abc123,def456
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

    else:
        print(f"Unknown command: {command}")
        print("Use 'python manage_system_user.py' to see available commands")


if __name__ == "__main__":
    main()
