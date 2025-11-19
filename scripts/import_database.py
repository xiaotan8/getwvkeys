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
import sqlite3
import sys
from pathlib import Path

# Add the parent directory to the path so we can import from getwvkeys
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask

from getwvkeys.config import SQLALCHEMY_DATABASE_URI
from getwvkeys.libraries import Library
from getwvkeys.models.Shared import db


def create_app():
    """Create a minimal Flask app for database operations"""
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    return app


def validate_database_file(file_path):
    """Validate the database file."""
    valid_extensions = [".db", ".sqlite", ".sqlite3", ".db3"]

    # Check if file exists
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return False

    # Check file extension
    file_ext = Path(file_path).suffix.lower()
    if file_ext not in valid_extensions:
        print(f"Error: Invalid file extension '{file_ext}'. Must be one of: {', '.join(valid_extensions)}")
        return False

    # Validate it's a valid SQLite database
    try:
        conn = sqlite3.connect(file_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = cursor.fetchall()
        conn.close()

        if not tables:
            print("Warning: Database file is valid but contains no tables (excluding system tables).")
        else:
            print(f"Database validated successfully. Found {len(tables)} table(s).")

        return True
    except sqlite3.DatabaseError as e:
        print(f"Error: Invalid SQLite database - {e}")
        return False


def preview_database(file_path: str, user_id: str = "CLI_IMPORT"):
    """Preview database contents without importing."""
    app = create_app()
    with app.app_context():
        try:
            library = Library(db)

            print(f"\n{'='*60}")
            print(f"Database Preview: {Path(file_path).name}")
            print(f"{'='*60}\n")

            result = library.import_keys_from_database(file_path, user_id, preview_mode=True)

            if not result.get("success"):
                print(f"Error: {result.get('error', 'Unknown error')}")
                return False

            summary = result["summary"]
            print(f"Total Tables: {summary['total_tables']}")
            print(f"Total Keys: {summary['total_keys']}")
            print(f"\n{'-'*60}")

            for table_info in result["tables"]:
                print(f"  Table: {table_info['name']}")
                print(f"     └─ Rows: {table_info['count']}")

            print(f"\n{'='*60}")
            print("Preview complete. No data was imported.")
            print(f"{'='*60}\n")
            return True

        except Exception as e:
            print(f"Error during preview: {e}")
            import traceback

            traceback.print_exc()
            return False


def import_database(file_path: str, user_id: str = "CLI_IMPORT"):
    """Import the database using the library logic."""
    app = create_app()
    with app.app_context():
        try:
            library = Library(db)

            print(f"\n{'='*60}")
            print(f"📥 Importing Database: {Path(file_path).name}")
            print(f"{'='*60}\n")

            # Progress callback to show updates
            def show_progress(message):
                print(f"  {message}")

            result = library.import_keys_from_database(
                file_path, user_id, preview_mode=False, progress_callback=show_progress
            )

            if not result.get("success"):
                print(f"❌ Error: {result.get('error', 'Unknown error')}")
                return False

            summary = result["summary"]
            print(f"\n{'='*60}")
            print(f"📊 Import Summary")
            print(f"{'='*60}")
            print(f"📊 Total Tables: {summary['total_tables']}")
            print(f"🔑 Total Keys Found: {summary['total_keys']}")
            print(f"✅ Keys Imported: {summary['imported_keys']}")
            print(f"⏭️  Keys Skipped: {summary['skipped_keys']} (duplicates)")

            if summary["imported_keys"] > 0:
                print(f"\n💾 Successfully imported {summary['imported_keys']} new keys to the database!")
            else:
                print(f"\n⚠️  No new keys were imported (all keys already exist).")

            print(f"\n{'='*60}")
            print("✅ Import complete!")
            print(f"{'='*60}\n")
            return True

        except Exception as e:
            print(f"❌ Error during import: {e}")
            import traceback

            traceback.print_exc()
            return False


def show_info(file_path: str):
    """Show detailed information about the database."""
    app = create_app()
    with app.app_context():
        try:
            library = Library(db)

            print(f"\n{'='*60}")
            print(f" Database Information: {Path(file_path).name}")
            print(f"{'='*60}\n")

            result = library.validate_sqlite_database(file_path)

            if not result.get("valid"):
                print(f"Error: {result.get('error', 'Unknown error')}")
                return False

            file_size = os.path.getsize(file_path)
            print(f"File: {file_path}")
            print(f"Size: {file_size / 1024:.2f} KB ({file_size / (1024*1024):.2f} MB)")
            print(f"Tables: {result['total_tables']}")
            print(f"Total Keys: {result['total_keys']}")
            print(f"\n{'-'*60}")
            print("Table Details:")
            print(f"{'-'*60}")

            for table_info in result["tables"]:
                print(f"  {table_info['name']:<30} {table_info['count']:>10} keys")

            print(f"\n{'='*60}\n")
            return True

        except Exception as e:
            print(f"Error getting info: {e}")
            return False


def main():
    if len(sys.argv) < 2:
        print(
            """
Database Import Utility

Usage:
  python import_database.py <command> <database_file> [user_id]

Commands:
  preview <file>              - Preview database structure without importing
  import <file> [user_id]     - Import database keys (default user_id: CLI_IMPORT)
  info <file>                 - Show detailed database information

Arguments:
  <file>                      - Path to SQLite database file (.db, .sqlite, .sqlite3, .db3)
  [user_id]                   - Optional: User ID to attribute imported keys to (default: CLI_IMPORT)

Examples:
  python import_database.py preview my_keys.db
  python import_database.py import my_keys.db
  python import_database.py import my_keys.db USER123
  python import_database.py info my_keys.db

File Requirements:
  - Must be a valid SQLite database
  - Tables must have columns: id (INTEGER), kid, key_
  - Supported extensions: .db, .sqlite, .sqlite3, .db3
"""
        )
        return

    command = sys.argv[1].lower()

    if command not in ["preview", "import", "info"]:
        print(f"Unknown command: {command}")
        print("Use 'python import_database.py' to see available commands")
        return

    if len(sys.argv) < 3:
        print(f"Error: Please provide a database file path")
        print("Usage: python import_database.py {command} <database_file>")
        return

    file_path = sys.argv[2]

    # Validate file first
    if not validate_database_file(file_path):
        return

    if command == "preview":
        preview_database(file_path)

    elif command == "import":
        user_id = sys.argv[3] if len(sys.argv) > 3 else "CLI_IMPORT"
        print(f"Importing keys as user: {user_id}")
        import_database(file_path, user_id)

    elif command == "info":
        show_info(file_path)


if __name__ == "__main__":
    main()
