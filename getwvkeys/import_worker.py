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

import logging
import os
import sqlite3
import tempfile
import threading
import time
import uuid

from getwvkeys.models.ImportTask import ImportTask
from getwvkeys.models.Shared import db
from getwvkeys.utils import CachedKey

logger = logging.getLogger("getwvkeys")


class ImportWorker:
    """Background worker for processing database imports"""

    def __init__(self, library, app):
        self.library = library
        self.app = app
        self.running = False
        self.thread = None

    def start(self):
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.thread.start()
        logger.info("Import worker started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Import worker stopped")

    def is_alive(self):
        return self.thread is not None and self.thread.is_alive()

    def get_status(self):
        return {
            "running": self.running,
            "thread_alive": self.is_alive(),
            "thread_name": self.thread.name if self.thread else None,
        }

    def _worker_loop(self):
        logger.info("Import worker loop started")
        while self.running:
            task = None
            try:
                with self.app.app_context():
                    task = ImportTask.query.filter_by(status="pending").order_by(ImportTask.created_at).first()

                    if task:
                        logger.info(f"Found pending task {task.id}, starting processing")
                        try:
                            self._process_task(task)
                        except Exception as e:
                            logger.exception(f"Error processing task {task.id}: {e}")
                            task.status = "failed"
                            task.error_message = str(e)
                            task.completed_at = int(time.time())
                            db.session.commit()

            except Exception as e:
                logger.exception(f"Error in import worker loop: {e}")

            if not task:
                time.sleep(2)
            else:
                time.sleep(0.5)

    def _process_task(self, task: ImportTask):
        try:
            task.status = "running"
            task.started_at = int(time.time())
            db.session.commit()

            logger.info(f"Processing import task {task.id}: {task.filename}")

            temp_dir = tempfile.gettempdir()
            temp_path = os.path.join(temp_dir, f"import_{task.id}.db")

            if not os.path.exists(temp_path):
                raise Exception(f"Import file not found: {temp_path}")

            validation_result = self.library.validate_sqlite_database(temp_path)

            if not validation_result["valid"]:
                raise Exception(validation_result["error"])

            task.total_tables = validation_result["total_tables"]
            task.total_keys = validation_result["total_keys"]
            db.session.commit()

            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()

            batch_size = 10000
            current_time = int(time.time())

            for table_info in validation_result["tables"]:
                table_name = table_info["name"]
                table_total = table_info["count"]

                task.current_table = table_name
                db.session.commit()

                offset = 0
                while offset < table_total:
                    cached_keys = []

                    cursor.execute(f"SELECT kid, key_ FROM {table_name} LIMIT {batch_size} OFFSET {offset}")
                    rows = cursor.fetchall()

                    if not rows:
                        break

                    for kid, key in rows:
                        task.processed_keys += 1

                        if not kid or not key:
                            task.skipped_keys += 1
                            continue

                        kid_clean = str(kid).replace("-", "").lower()
                        if len(kid_clean) != 32:
                            task.skipped_keys += 1
                            continue

                        cached_keys.append(
                            CachedKey(
                                kid=kid_clean,
                                added_at=current_time,
                                added_by=task.user_id,
                                license_url=f"http://DATABASE_IMPORT_{table_name}.local",
                                key=str(key),
                            )
                        )

                    if cached_keys:
                        batch_imported = self.library.cache_keys(cached_keys)
                        task.imported_keys += batch_imported
                        batch_skipped = len(cached_keys) - batch_imported
                        task.skipped_keys += batch_skipped

                    offset += batch_size
                    db.session.commit()

            conn.close()

            try:
                os.remove(temp_path)
            except Exception as e:
                logger.warning(f"Failed to remove temp file {temp_path}: {e}")

            task.status = "completed"
            task.completed_at = int(time.time())
            db.session.commit()

            logger.info(f"Completed import task {task.id}: imported={task.imported_keys}, skipped={task.skipped_keys}")

        except Exception as e:
            logger.exception(f"Error processing import task {task.id}: {e}")
            task.status = "failed"
            task.error_message = str(e)
            task.completed_at = int(time.time())
            db.session.commit()

    def create_task(self, user_id: str, filename: str, file_path: str) -> str:
        with self.app.app_context():
            task_id = str(uuid.uuid4())
            temp_dir = tempfile.gettempdir()
            temp_path = os.path.join(temp_dir, f"import_{task_id}.db")

            import shutil

            shutil.copy2(file_path, temp_path)

            task = ImportTask(
                id=task_id,
                user_id=user_id,
                filename=filename,
                status="pending",
                created_at=int(time.time()),
            )

            db.session.add(task)
            db.session.commit()

            logger.info(f"Created import task {task_id} for user {user_id}: {filename}")
            return task_id
