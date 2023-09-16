"""
 This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
 Copyright (C) 2022-2023 Notaghost, Puyodead1 and GetWVKeys contributors 
 
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


class APIKey(db.Model):
    __tablename__ = "apikeys"
    id = db.Column(db.Integer, primary_key=True, nullable=False, unique=True, autoincrement=True)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.now())
    api_key = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.String(255), db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User", back_populates="api_keys")
