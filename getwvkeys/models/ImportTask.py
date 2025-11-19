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

from getwvkeys.models.Shared import db


class ImportTask(db.Model):
    __tablename__ = "import_tasks"

    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending, running, completed, failed
    current_table = db.Column(db.String(255), nullable=True)
    total_tables = db.Column(db.Integer, default=0)
    total_keys = db.Column(db.Integer, default=0)
    processed_keys = db.Column(db.Integer, default=0)
    imported_keys = db.Column(db.Integer, default=0)
    skipped_keys = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.Integer, nullable=False)
    started_at = db.Column(db.Integer, nullable=True)
    completed_at = db.Column(db.Integer, nullable=True)

    def to_dict(self):
        progress_percent = 0
        if self.total_keys > 0:
            progress_percent = int((self.processed_keys / self.total_keys) * 100)

        return {
            "id": self.id,
            "user_id": self.user_id,
            "filename": self.filename,
            "status": self.status,
            "current_table": self.current_table,
            "total_tables": self.total_tables,
            "total_keys": self.total_keys,
            "processed_keys": self.processed_keys,
            "imported_keys": self.imported_keys,
            "skipped_keys": self.skipped_keys,
            "progress_percent": progress_percent,
            "error_message": self.error_message,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }
