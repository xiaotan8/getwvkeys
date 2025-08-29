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
from google.protobuf.message import DecodeError
from pyplayready import PSSH as PlayreadyPSSH
from pyplayready import Cdm as PlayreadyCdm
from pyplayready import Device as PlayreadyDevice
from pyplayready import InvalidInitData as PlayreadyInvalidInitData
from pyplayready import InvalidLicense as PlayreadyInvalidLicense
from pyplayready import InvalidPssh as PlayreadyInvalidPssh
from pyplayready import InvalidSession as PlayReadyInvalidSession
from pyplayready import TooManySessions as PlayReadyTooManySessions
from pywidevine import PSSH as WidevinePSSH
from pywidevine import Cdm as WidevineCdm
from pywidevine import Device as WidevineDevice
from pywidevine.exceptions import InvalidContext as WidevineInvalidContext
from pywidevine.exceptions import InvalidInitData as WidevineInvalidInitData
from pywidevine.exceptions import InvalidLicenseMessage as WidevineInvalidLicenseMessage
from pywidevine.exceptions import InvalidLicenseType as WidevineInvalidLicenseType
from pywidevine.exceptions import InvalidSession as WidevineInvalidSession
from pywidevine.exceptions import SignatureMismatch as WidevineSignatureMismatch
from pywidevine.exceptions import TooManySessions as WidevineTooManySessions
from sqlalchemy import func, text
from werkzeug.exceptions import BadRequest

from getwvkeys import config
from getwvkeys.models.APIKey import APIKey as APIKeyModel
from getwvkeys.models.Key import Key as KeyModel
from getwvkeys.models.KeyCount import KeyCount as KeyCountModel
from getwvkeys.models.PRD import PRD
from getwvkeys.models.User import User as UserModel
from getwvkeys.models.WVD import WVD
from getwvkeys.user import FlaskUser
from getwvkeys.utils import CachedKey, DRMType

# set the custom max session count
PlayreadyCdm.MAX_NUM_OF_SESSIONS = config.MAX_SESSIONS
WidevineCdm.MAX_NUM_OF_SESSIONS = config.MAX_SESSIONS

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


# def is_custom_buildinfo(buildinfo):
#     return next(
#         (
#             True
#             for entry in config.EXTERNAL_API_BUILD_INFOS
#             if entry["buildinfo"] == buildinfo
#         ),
#         False,
#     )


class Library:
    SYSTEM_WVDS: list[WVD] = []
    SYSTEM_PRDS: list[PRD] = []

    def __init__(self, db: SQLAlchemy):
        self.db = db

    def get_random_wvd(self):
        if len(self.SYSTEM_WVDS) == 0:
            raise Exception("No WVDs configured for rotation")
        return secrets.choice(self.SYSTEM_WVDS)

    def get_random_prd(self):
        print(self.SYSTEM_PRDS)
        if len(self.SYSTEM_PRDS) == 0:
            raise Exception("No PRDs configured for rotation")
        return secrets.choice(self.SYSTEM_PRDS)

    def is_user_prd(self, device: str):
        return next((False for entry in self.SYSTEM_PRDS if entry["code"] == device), False)

    def is_user_wvd(self, device: str):
        return next((False for entry in self.SYSTEM_WVDS if entry["code"] == device), False)

    def cache_keys(self, cached_keys: list[CachedKey]):
        added_count = 0
        for cached_key in cached_keys:
            if self.cache_key(cached_key):
                added_count += 1

        # Increment the cached count by the total number of added keys
        if added_count > 0:
            self.increment_cached_keycount(added_count)

        return added_count

    def cache_key(self, cached_key: CachedKey):
        # do not add existing kid and key_ pairs
        if KeyModel.query.filter_by(kid=cached_key.kid, key_=cached_key.key).first():
            return False  # Return False if key already exists
        k = KeyModel(
            kid=cached_key.kid,
            added_at=cached_key.added_at,
            added_by=cached_key.added_by,
            license_url=cached_key.license_url,
            key_=cached_key.key,
        )
        self.db.session.merge(k)
        self.db.session.commit()
        return True  # Return True if key was added

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

    def get_cached_keycount(self):
        """Get the cached key count from the database"""
        cache_entry = KeyCountModel.query.first()
        if not cache_entry:
            # Initialize cache if it doesn't exist
            self.update_cached_keycount()
            cache_entry = KeyCountModel.query.first()
        return cache_entry.count_value if cache_entry else 0

    def update_cached_keycount(self):
        """Update the cached key count with the current actual count"""
        actual_count = KeyModel.query.count()
        cache_entry = KeyCountModel.query.first()

        if cache_entry:
            cache_entry.count_value = actual_count
            cache_entry.last_updated = int(time.time())
        else:
            cache_entry = KeyCountModel(count_value=actual_count, last_updated=int(time.time()))
            self.db.session.add(cache_entry)

        self.db.session.commit()
        logger.info(f"Updated cached key count to {actual_count}")

    def increment_cached_keycount(self, increment=1):
        """Increment the cached key count by the specified amount"""
        cache_entry = KeyCountModel.query.first()

        if cache_entry:
            cache_entry.count_value += increment
            cache_entry.last_updated = int(time.time())
        else:
            # Initialize cache if it doesn't exist
            self.update_cached_keycount()
            return

        self.db.session.commit()

    def should_refresh_cache(self, max_age_seconds=3600):
        """Check if the cache should be refreshed based on age"""
        cache_entry = KeyCountModel.query.first()
        if not cache_entry:
            return True

        current_time = int(time.time())
        age = current_time - cache_entry.last_updated
        return age > max_age_seconds

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
        results = {
            "kid": kid,
            "keys": list(),
        }
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
                    "key": f"{key.kid}:{key.key_}",
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

    def assign_system_wvd(self, wvd_data: str) -> str:
        """Assign a WVD to the system user"""

        system_user = FlaskUser.get_system_user(self.db)
        hash_val = self.upload_wvd(wvd_data, system_user.id)

        # Refresh rotation config cache since system devices changed
        self.build_rotation_config_cache()

        return hash_val

    def assign_system_prd(self, prd_data: str) -> str:
        """Assign a PRD to the system user"""

        system_user = FlaskUser.get_system_user(self.db)
        hash_val = self.upload_prd(prd_data, system_user.id)

        # Refresh rotation config cache since system devices changed
        self.build_rotation_config_cache()

        return hash_val

    def get_system_devices(self):
        """Get all devices owned by the system user"""

        system_user = FlaskUser.get_system_user(self.db)
        return {"wvds": system_user.get_user_wvds(), "prds": system_user.get_user_prds()}

    def migrate_devices_to_system(self, device_hashes: list, device_type: str):
        """Migrate existing devices to system user ownership"""

        system_user = FlaskUser.get_system_user(self.db)

        if device_type.lower() == "wvd":
            for hash_val in device_hashes:
                device = WVD.query.filter_by(hash=hash_val).first()
                if device:
                    device.uploaded_by = system_user.id
                    if device not in system_user.user_model.wvds:
                        system_user.user_model.wvds.append(device)

        elif device_type.lower() == "prd":
            for hash_val in device_hashes:
                device = PRD.query.filter_by(hash=hash_val).first()
                if device:
                    device.uploaded_by = system_user.id
                    if device not in system_user.user_model.prds:
                        system_user.user_model.prds.append(device)

        self.db.session.commit()

        # Refresh rotation config cache since system devices changed
        self.build_rotation_config_cache()

        logger.info(f"Migrated {len(device_hashes)} {device_type.upper()} devices to system user")

    def get_rotation_devices(self) -> tuple[list[str], list[str]]:
        """Get all devices enabled for rotation (only system user devices)"""

        system_user = FlaskUser.get_system_user(self.db)

        # Get WVDs enabled for rotation owned by system user
        wvds: list[WVD] = WVD.query.filter_by(uploaded_by=system_user.id, enabled_for_rotation=True).all()

        # Get PRDs enabled for rotation owned by system user
        prds: list[PRD] = PRD.query.filter_by(uploaded_by=system_user.id, enabled_for_rotation=True).all()

        # only hash
        wvd_hashes = [x.hash for x in wvds]
        prd_hashes = [x.hash for x in prds]
        return (wvd_hashes, prd_hashes)

    def set_device_rotation_status(self, device_id: int, device_type: str, enabled: bool):
        """Enable or disable a device for rotation (only system user devices)"""

        system_user = FlaskUser.get_system_user(self.db)

        if device_type.lower() == "wvd":
            device = WVD.query.filter_by(id=device_id, uploaded_by=system_user.id).first()
        elif device_type.lower() == "prd":
            device = PRD.query.filter_by(id=device_id, uploaded_by=system_user.id).first()
        else:
            raise BadRequest("Invalid device type")

        if not device:
            raise BadRequest("Device not found or not owned by system user")

        device.enabled_for_rotation = enabled
        self.db.session.commit()

        logger.info(f"Set {device_type.upper()} device {device_id} rotation status to {enabled}")
        return device

    def build_rotation_config_cache(self) -> list[str]:
        """Build and cache the rotation device configuration"""
        wvds, prds = self.get_rotation_devices()

        self.SYSTEM_WVDS = wvds
        self.SYSTEM_PRDS = prds

        logger.info(f"Updated rotation config cache: {len(wvds)} WVDs, {len(prds)} PRDs")
        return (wvds, prds)

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

    def remote_cdm_get_device(
        self, device_name: str, get_random_fn: callable
    ) -> Union[WidevineDevice, PlayreadyDevice]:
        device = None

        if device_name == "getwvkeys":
            device_name = get_random_fn()
            device = self.get_device_by_hash(device_name)
        else:
            device = self.get_device_by_hash(device_name)

        if not device:
            raise Exception(f"Device '{device_name}' not found")

        if isinstance(device, PRD):
            return PlayreadyDevice.loads(device.prd)
        elif isinstance(device, WVD):
            return WidevineDevice.loads(device.wvd)

        raise BadRequest("invalid device type")

    def remote_cdm_get_keys_impl(self, cdm: Union[WidevineCdm, PlayreadyCdm], session_id: bytes, key_type: str):
        if isinstance(cdm, WidevineCdm):
            if key_type == "ALL":
                key_type = None
            keys = cdm.get_keys(session_id, key_type)
            keys_json = [
                {
                    "key_id": key.kid.hex,
                    "key": key.key.hex(),
                    "type": key.type,
                    "permissions": key.permissions,
                }
                for key in keys
                if not key_type or key.type == key_type
            ]
            return keys_json

        elif isinstance(cdm, PlayreadyCdm):
            keys = cdm.get_keys(session_id)

            keys_json = [
                {
                    "key_id": key.key_id.hex,
                    "key": key.key.hex(),
                    "type": key.key_type.value,
                    "cipher_type": key.cipher_type.value,
                    "key_length": key.key_length,
                }
                for key in keys
            ]

            return keys_json

    def remote_cdm_open_session(
        self, device: Union[WidevineDevice, PlayreadyDevice], cdm_class: Union[WidevineCdm, PlayreadyCdm]
    ):
        cdm = cdm_class.from_device(device)
        session_id = cdm.open()
        session_id = session_id.hex()
        # store the session
        sessions[session_id] = cdm

        return session_id

    def remote_cdm_parse_init_data(self, cdm_id: str, init_data: str) -> Union[WidevinePSSH, PlayreadyPSSH]:
        if cdm_id == "widevine":
            return WidevinePSSH(init_data)
        else:
            return PlayreadyPSSH(init_data)

    def remote_cdm_get_challenge(
        self, cdm: Union[WidevineCdm, PlayreadyCdm], session_id: bytes, init_data: str, license_type: str
    ):
        if isinstance(cdm, WidevineCdm):
            pssh = WidevinePSSH(init_data)
            challenge = cdm.get_license_challenge(
                session_id=session_id, pssh=pssh, license_type=license_type, privacy_mode=True
            )
            return jsonify(
                {"status": 200, "message": "Success", "data": {"challenge_b64": base64.b64encode(challenge).decode()}}
            )
        elif isinstance(cdm, PlayreadyCdm):
            if not init_data.startswith("<WRMHEADER"):
                try:
                    pssh = PlayreadyPSSH(init_data)
                    if pssh.wrm_headers:
                        init_data = pssh.wrm_headers[0]
                except PlayreadyInvalidPssh as e:
                    return jsonify({"status": 500, "message": f"Unable to parse PSSH: {e}"})
            challenge = cdm.get_license_challenge(
                session_id=session_id,
                wrm_header=init_data,
            )

            return jsonify({"status": 200, "message": "Success", "data": {"challenge": challenge}})

        raise BadRequest("Invalid cdm")

    def remote_cdm_open(self, cdm_id: str, device_name: str):
        try:
            if cdm_id == "widevine":
                device = self.remote_cdm_get_device(device_name, self.get_random_wvd)
                session_id = self.remote_cdm_open_session(device, WidevineCdm)
            else:
                device = self.remote_cdm_get_device(device_name, self.get_random_prd)
                session_id = self.remote_cdm_open_session(device, PlayreadyCdm)
        except (WidevineTooManySessions, PlayReadyTooManySessions):
            return (
                jsonify(
                    {
                        "status": 429,
                        "message": "Too many sessions for this device. Please try again later.",
                    }
                ),
                429,
            )
        # except Exception as e:
        #     logger.exception(e)
        #     return (
        #         jsonify(
        #             {
        #                 "status": 500,
        #                 "message": str(e),
        #             }
        #         ),
        #         500,
        #     )

        return jsonify(
            {
                "status": 200,
                "message": "Success",
                "data": {
                    "session_id": session_id,
                    "device": {"system_id": 666, "security_level": device.security_level},
                },
            }
        )

    def remote_cdm_close(self, cdm_id: str, device_name: str, session_id: bytes):
        cdm = sessions.get(session_id.hex())
        if not cdm:
            return (
                jsonify(
                    {
                        "status": 404,
                        "message": f"Session '{session_id}' not found.",
                    }
                ),
                404,
            )

        try:
            cdm.close(session_id)
        except (WidevineInvalidSession, PlayReadyInvalidSession):
            return (
                jsonify(
                    {
                        "status": 400,
                        "message": f"Invalid Session ID '{session_id.hex()}', it may have expired.",
                    }
                ),
                400,
            )
        return jsonify({"status": 200, "message": f"Successfully closed Session '{session_id.hex()}'."})

    def remote_cdm_set_service_certificate(self, cdm_id: str, device_name: str, session_id: bytes, certificate: str):
        cdm = sessions.get(session_id.hex())
        if not cdm:
            return (
                jsonify(
                    {
                        "status": 404,
                        "message": f"Session '{session_id}' not found.",
                    }
                ),
                404,
            )

        try:
            provider_id = cdm.set_service_certificate(session_id, certificate)
        except WidevineInvalidSession:
            return (
                jsonify({"status": 400, "message": f"Invalid Session ID '{session_id.hex()}', it may have expired."}),
                400,
            )
        except DecodeError as e:
            return (
                jsonify({"status": 400, "message": f"Invalid Service Certificate: {e}"}),
                400,
            )
        except WidevineSignatureMismatch:
            return (jsonify({"status": 400, "message": "Signature Validation failed on the Service Certificate"}), 400)

        return jsonify(
            {
                "status": 200,
                "message": f"Successfully {['set', 'unset'][not certificate]} the Service Certificate.",
                "data": {"provider_id": provider_id},
            }
        )

    def remote_cdm_get_service_certificate(self, cdm_id: str, device_name: str, session_id: bytes):
        cdm = sessions.get(session_id.hex())
        if not cdm:
            return (
                jsonify(
                    {
                        "status": 404,
                        "message": f"Session '{session_id}' not found.",
                    }
                ),
                404,
            )

        try:
            certificate = cdm.get_service_certificate(session_id)
        except WidevineInvalidSession:
            return (
                jsonify({"status": 400, "message": f"Invalid Session ID '{session_id.hex()}', it may have expired."}),
                400,
            )

        certificate_b64 = None
        if certificate:
            certificate_b64 = base64.b64encode(certificate.SerializeToString()).decode()

        return jsonify(
            {
                "status": 200,
                "message": "Successfully got the Service Certificate.",
                "data": {"service_certificate": certificate_b64},
            }
        )

    def remote_cdm_license_challenge(
        self, cdm_id: str, device_name: str, license_type: str, session_id: str, init_data: str
    ):
        cdm = sessions.get(session_id.hex())
        if not cdm:
            return (
                jsonify(
                    {
                        "status": 404,
                        "message": f"Session '{session_id}' not found.",
                    }
                ),
                404,
            )

        # TODO: enforce privacy mode option?

        try:
            return self.remote_cdm_get_challenge(cdm, session_id, init_data, license_type)
        except (PlayreadyInvalidPssh, PlayreadyInvalidInitData, WidevineInvalidInitData) as e:
            return jsonify(
                {
                    "status": 400,
                    "message": f"Unable to parse base64 PSSH: {str(e)}",
                }
            )
        except (WidevineInvalidSession, PlayReadyInvalidSession):
            return (
                jsonify({"status": 400, "message": f"Invalid Session ID '{session_id.hex()}', it may have expired."}),
                400,
            )
        except WidevineInvalidLicenseType:
            return (
                jsonify({"status": 400, "message": f"Invalid License Type '{license_type}'."}),
                400,
            )

    def remote_cdm_parse_license(self, cdm_id: str, device_name: str, session_id: bytes, license_message: str):
        cdm = sessions.get(session_id.hex())
        if not cdm:
            return (
                jsonify(
                    {
                        "status": 404,
                        "message": f"Session '{session_id}' not found.",
                    }
                ),
                404,
            )

        try:
            cdm.parse_license(session_id, license_message)
        except (WidevineInvalidSession, PlayReadyInvalidSession):
            return (
                jsonify({"status": 400, "message": f"Invalid Session ID '{session_id.hex()}', it may have expired."}),
                400,
            )
        except (WidevineInvalidLicenseMessage, PlayreadyInvalidLicense) as e:
            return (
                jsonify({"status": 400, "message": f"Invalid License: {e}"}),
                400,
            )
        except WidevineInvalidContext as e:
            return (
                jsonify({"status": 400, "message": f"Invalid Context: {e}"}),
                400,
            )
        except WidevineSignatureMismatch:
            return (
                jsonify({"status": 400, "message": "Signature Validation failed on the License message"}),
                400,
            )
        return jsonify({"status": 200, "message": "Successfully parsed and loaded the Keys from the License message."})

    def remote_cdm_get_keys(
        self, cdm_id: str, device_name: str, key_type: str, session_id: bytes, user_id: Union[str, None]
    ):
        cdm = sessions.get(session_id.hex())
        if not cdm:
            return (
                jsonify(
                    {
                        "status": 404,
                        "message": f"Session '{session_id}' not found.",
                    }
                ),
                404,
            )

        try:
            keys = self.remote_cdm_get_keys_impl(cdm, session_id, key_type)
            self.cache_keys(
                [
                    CachedKey(
                        key["key_id"],
                        int(time.time()),
                        user_id,
                        "http://REMOTECDM.local",
                        key["key"],
                    )
                    for key in keys
                ]
            )
            return jsonify({"status": 200, "message": "Success", "data": {"keys": keys}})
        except (WidevineInvalidSession, PlayReadyInvalidSession):
            return (
                jsonify({"status": 400, "message": f"Invalid Session ID '{session_id.hex()}', it may have expired."}),
                400,
            )
        except ValueError as e:
            return (
                jsonify({"status": 400, "message": f"Invalid Key Type '{key_type}': {e}"}),
                400,
            )
