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

import base64
import hashlib
import logging
import secrets
import time
import uuid
from typing import Union
from urllib.parse import urlsplit

from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from pyplayready import PSSH as PlayreadyPSSH
from pyplayready import Cdm as PlayreadyCdm
from pyplayready import Device as PlayreadyDevice
from pyplayready.exceptions import InvalidInitData as PlayreadyInvalidInitData
from pyplayready.exceptions import InvalidPssh as PlayreadyInvalidPssh
from pywidevine import PSSH as WidevinePSSH
from pywidevine import Cdm as WidevineCdm
from pywidevine import Device as WidevineDevice
from sqlalchemy import func, text
from werkzeug.exceptions import BadRequest

from getwvkeys import config
from getwvkeys.models.APIKey import APIKey as APIKeyModel
from getwvkeys.models.Key import Key as KeyModel
from getwvkeys.models.PRD import PRD
from getwvkeys.models.User import User as UserModel
from getwvkeys.models.WVD import WVD
from getwvkeys.utils import CachedKey, DRMType

logger = logging.getLogger("getwvkeys")

common_privacy_cert = (
    "CAUSxwUKwQIIAxIQFwW5F8wSBIaLBjM6L3cqjBiCtIKSBSKOAjCCAQoCggEBAJntWzsyfateJO/DtiqVtZhSCtW8y"
    "zdQPgZFuBTYdrjfQFEEQa2M462xG7iMTnJaXkqeB5UpHVhYQCOn4a8OOKkSeTkwCGELbxWMh4x+Ib/7/up34QGeHl"
    "eB6KRfRiY9FOYOgFioYHrc4E+shFexN6jWfM3rM3BdmDoh+07svUoQykdJDKR+ql1DghjduvHK3jOS8T1v+2RC/TH"
    "hv0CwxgTRxLpMlSCkv5fuvWCSmvzu9Vu69WTi0Ods18Vcc6CCuZYSC4NZ7c4kcHCCaA1vZ8bYLErF8xNEkKdO7Dev"
    "Sy8BDFnoKEPiWC8La59dsPxebt9k+9MItHEbzxJQAZyfWgkCAwEAAToUbGljZW5zZS53aWRldmluZS5jb20SgAOuN"
    "HMUtag1KX8nE4j7e7jLUnfSSYI83dHaMLkzOVEes8y96gS5RLknwSE0bv296snUE5F+bsF2oQQ4RgpQO8GVK5uk5M"
    "4PxL/CCpgIqq9L/NGcHc/N9XTMrCjRtBBBbPneiAQwHL2zNMr80NQJeEI6ZC5UYT3wr8+WykqSSdhV5Cs6cD7xdn9"
    "qm9Nta/gr52u/DLpP3lnSq8x2/rZCR7hcQx+8pSJmthn8NpeVQ/ypy727+voOGlXnVaPHvOZV+WRvWCq5z3CqCLl5"
    "+Gf2Ogsrf9s2LFvE7NVV2FvKqcWTw4PIV9Sdqrd+QLeFHd/SSZiAjjWyWOddeOrAyhb3BHMEwg2T7eTo/xxvF+YkP"
    "j89qPwXCYcOxF+6gjomPwzvofcJOxkJkoMmMzcFBDopvab5tDQsyN9UPLGhGC98X/8z8QSQ+spbJTYLdgFenFoGq4"
    "7gLwDS6NWYYQSqzE3Udf2W7pzk4ybyG4PHBYV3s4cyzdq8amvtE/sNSdOKReuHpfQ="
)

wv_sessions: dict[str, WidevineCdm] = dict()
pr_sessions: dict[str, PlayreadyCdm] = dict()
sessions: dict[str, Union[WidevineCdm, PlayreadyCdm]] = dict()


def get_random_wvd():
    if len(config.DEFAULT_WVDS) == 0:
        raise Exception("No WVDs configured")
    return secrets.choice(config.DEFAULT_WVDS)


def get_random_prd():
    if len(config.DEFAULT_PRDS) == 0:
        raise Exception("No PRDs configured")
    return secrets.choice(config.DEFAULT_PRDS)


# def is_custom_buildinfo(buildinfo):
#     return next(
#         (
#             True
#             for entry in config.EXTERNAL_API_BUILD_INFOS
#             if entry["buildinfo"] == buildinfo
#         ),
#         False,
#     )


def is_user_prd(device: str):
    return next((False for entry in config.DEFAULT_PRDS if entry["code"] == device), False)


def is_user_wvd(device: str):
    return next((False for entry in config.DEFAULT_WVDS if entry["code"] == device), False)


class Library:
    def __init__(self, db: SQLAlchemy):
        self.db = db

    def cache_keys(self, cached_keys: list[CachedKey]):
        for cached_key in cached_keys:
            self.cache_key(cached_key)

    def cache_key(self, cached_key: CachedKey):
        # do not add existing kid and key_ pairs
        if KeyModel.query.filter_by(kid=cached_key.kid, key_=cached_key.key).first():
            return
        k = KeyModel(
            kid=cached_key.kid,
            added_at=cached_key.added_at,
            added_by=cached_key.added_by,
            license_url=cached_key.license_url,
            key_=cached_key.key,
        )
        self.db.session.merge(k)
        self.db.session.commit()

    def get_keycount_approx(self):
        sql = text(
            """
            SELECT table_rows 
            FROM information_schema.tables
            WHERE table_schema = :schema AND table_name = :table
        """
        )
        result = self.db.session.execute(
            sql,
            {
                "schema": self.db.engine.url.database,
                "table": KeyModel.__tablename__,
            },
        ).scalar()
        return result or 0

    def search(self, query: str) -> list:
        if query.startswith("AAAA"):
            # Try to parse the query as a PSSH and extract a KID
            # try to parse as a playready pssh
            try:
                pssh = PlayreadyPSSH(query)
                kids = [x.read_attributes()[0] for x in pssh.wrm_headers]
                kid = kids[0][0].value
                decoded_kid = base64.b64decode(kid)
                query = str(uuid.UUID(bytes_le=decoded_kid))
            except Exception:
                # try to parse as widevine pssh
                try:
                    pssh = WidevinePSSH(query)
                    if not pssh.key_ids or len(pssh.key_ids) == 0:
                        raise BadRequest("Invalid PSSH: No key IDs found")
                    query = pssh.key_ids[0].hex
                except Exception as e:
                    logger.exception(e)
                    raise BadRequest(f"Invalid PSSH: {e}")

        if "-" in query:
            query = query.replace("-", "")
        return KeyModel.query.filter_by(kid=query).all()

    def search_res_to_dict(self, kid: str, keys: list[KeyModel]) -> dict:
        """
        Converts a list of Keys from search method to a list of dicts
        """
        results = {"kid": kid, "keys": list()}
        for key in keys:
            license_url = key.license_url
            if license_url:
                s = urlsplit(key.license_url)
                license_url = "{}://{}".format(s.scheme, s.netloc)
            results["keys"].append(
                {
                    "added_at": key.added_at,
                    # We shouldnt return the license url as that could have sensitive information it in still
                    "license_url": license_url,
                    "key": key.key_,
                }
            )
        return results

    # def cdm_selector(self, code: str) -> dict:
    #     cdm = CDMModel.query.filter_by(code=code).first()
    #     if not cdm:
    #         raise NotFound("CDM not found")
    #     return cdm.to_json()

    # def update_cdm(self, client_id_blob, device_private_key, uploaded_by) -> str:
    #     from getwvkeys.pywidevine.cdm.formats import wv_proto2_pb2

    #     def get_blob_id(blob):
    #         blob_ = base64.b64decode(blob)
    #         ci = wv_proto2_pb2.ClientIdentification()
    #         ci.ParseFromString(blob_)
    #         return (
    #             str(ci.ClientInfo[5])
    #             .split("Value: ")[1]
    #             .replace("\n", "")
    #             .replace('"', "")
    #         )

    #     code = get_blob_id(client_id_blob)
    #     cdm = CDMModel(
    #         client_id_blob_filename=client_id_blob,
    #         device_private_key=device_private_key,
    #         code=code,
    #         uploaded_by=uploaded_by,
    #     )
    #     self.db.session.add(cdm)
    #     self.db.session.commit()
    #     return code

    def get_device_by_hash(self, device_hash: str):
        print(device_hash)
        # try to get prd or wvd by hash
        device = PRD.query.filter_by(hash=device_hash).first()
        if device:
            return device

        device = WVD.query.filter_by(hash=device_hash).first()
        if device:
            return device

        raise BadRequest("Device not found")

    def get_device_drm_type(self, device_hash: str) -> DRMType:
        """
        Returns the type of device by its hash.
        """
        device: Union[PRD, WVD] = self.get_device_by_hash(device_hash)
        if not device:
            return DRMType.INVALID

        if isinstance(device, PRD):
            return DRMType.PLAYREADY
        elif isinstance(device, WVD):
            return DRMType.WIDEVINE
        else:
            return DRMType.INVALID

    def get_pssh_drm_type(self, pssh: Union[str, bytes]) -> DRMType:
        """
        Returns the type of DRM system based on the PSSH.
        """
        try:
            PlayreadyPSSH(pssh)
            return DRMType.PLAYREADY
        except (PlayreadyInvalidPssh, PlayreadyInvalidInitData):
            pass

        try:
            WidevinePSSH(pssh)
            return DRMType.WIDEVINE
        except Exception as e:
            pass

        return DRMType.INVALID

    def upload_prd(self, prd_data: str, user_id: str) -> str:
        user = UserModel.query.filter_by(id=user_id).first()
        if not user:
            raise BadRequest("User not found")

        # used to check if the prd is valid
        try:
            PlayreadyDevice.loads(prd_data)
        except Exception as e:
            logger.exception(e)
            raise BadRequest(f"Invalid PRD")

        prd_raw = base64.b64decode(prd_data)

        # calculate the hash of the prd
        prd_hash = hashlib.sha256(prd_raw).hexdigest()

        # get device
        device = PRD.query.filter_by(hash=prd_hash).first()
        if not device:
            device = PRD(uploaded_by=user.id, prd=prd_data, hash=prd_hash)
            self.db.session.add(device)
            user.prds.append(device)
            self.db.session.commit()
        elif device not in user.prds:
            # add device to user if its not already there
            user.prds.append(device)
            self.db.session.commit()
        else:
            raise BadRequest("PRD already uploaded, please use the existing hash found on the profile page.")

        return device.hash

    def upload_wvd(self, wvd_data: str, user_id: str) -> str:
        user = UserModel.query.filter_by(id=user_id).first()
        if not user:
            raise BadRequest("User not found")

        # used to check if the wvd is valid
        try:
            WidevineDevice.loads(wvd_data)
        except Exception as e:
            logger.exception(e)
            raise BadRequest(f"Invalid WVD")

        wvd_raw = base64.b64decode(wvd_data)

        # calculate the hash of the wvd
        wvd_hash = hashlib.sha256(wvd_raw).hexdigest()

        # get device
        device = WVD.query.filter_by(hash=wvd_hash).first()
        if not device:
            device = WVD(uploaded_by=user.id, wvd=wvd_data, hash=wvd_hash)
            self.db.session.add(device)
            user.wvds.append(device)
            self.db.session.commit()
        elif device not in user.wvds:
            # add device to user if its not already there
            user.wvds.append(device)
            self.db.session.commit()
        else:
            raise BadRequest("WVD already uploaded, please use the existing hash found on the profile page.")

        return device.hash

    def add_keys(self, keys: list, user_id: str):
        cached_keys = list()

        for entry in keys:
            (added_at, licese_url, key) = (
                entry.get("time", int(time.time())),
                entry.get("license_url", "MANUAL ENTRY"),
                entry.get("key"),
            )
            (kid, _) = key.split(":")
            cached_keys.append(CachedKey(kid, added_at, user_id, licese_url, key))

        self.cache_keys(cached_keys)
        return (
            jsonify({"error": False, "message": "Added {} keys".format(len(keys))}),
            201,
        )

    def get_prd_by_hash(self, hash: str):
        return PRD.query.filter_by(hash=hash).first()

    def get_wvd_by_hash(self, hash: str):
        return WVD.query.filter_by(hash=hash).first()
