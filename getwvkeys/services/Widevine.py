import base64
import json
import logging
import time
from urllib.parse import urlsplit

import requests
from flask import jsonify, render_template
from google.protobuf.message import DecodeError
from pywidevine import PSSH as WidevinePSSH
from pywidevine import Cdm as WidevineCdm
from pywidevine import Device as WidevineDevice
from pywidevine.exceptions import InvalidInitData as WidevineInvalidInitData
from pywidevine.exceptions import InvalidLicenseMessage as WidevineInvalidLicenseMessage
from pywidevine.exceptions import InvalidSession as WidevineInvalidSession
from pywidevine.exceptions import SignatureMismatch as WidevineSignatureMismatch
from pywidevine.exceptions import TooManySessions as WidevineTooManySessions
from requests.exceptions import ProxyError
from werkzeug.exceptions import BadRequest, InternalServerError

from getwvkeys.libraries import Library, wv_sessions
from getwvkeys.services.BaseService import BaseService
from getwvkeys.utils import CachedKey

logger = logging.getLogger("getwvkeys.widevine")


class Widevine(BaseService):
    def __init__(
        self,
        library: Library,
        user_id,
        device_hash,
        # TODO: we really shouldn't do this, but vinetrimmer doesn't send license urls without modifications
        license_url="VINETRIMMER",
        pssh=None,
        proxy={},
        headers={},
        force=False,
        response=None,
        challenge=False,
        server_certificate=None,
        session_id=None,
        is_web=False,
        is_curl=False,
    ):
        super().__init__(library)
        self.library = library
        self.license_url = license_url
        self.pssh: WidevinePSSH = WidevinePSSH(pssh)
        self.kid = None
        self.headers = headers
        self.device = device_hash
        self.force = force
        self.time = int(time.time())
        self.content_keys: list[CachedKey] = list()
        self.license_request = challenge
        self.license_response = response
        self.user_id = user_id
        self.server_certificate = server_certificate
        self.proxy = proxy
        if self.proxy and isinstance(self.proxy, str):
            self.proxy = {"http": self.proxy, "https": self.proxy}
        self.store_request = {}
        self.session_id = session_id
        self.is_web = is_web
        self.curl = is_curl

        try:
            if pssh:
                if self.pssh.key_ids and len(self.pssh.key_ids) > 0:
                    self.kid = self.pssh.key_ids[0].hex
                else:
                    self.force = True
        except DecodeError:
            raise BadRequest("Invalid PSSH")

    @staticmethod
    def post_data(license_url, headers, data, proxy):
        try:
            r = requests.post(
                url=license_url,
                data=data,
                headers=headers,
                proxies=proxy,
                timeout=10,
            )
            if r.status_code != 200:
                raise BadRequest(f"Failed to get license: {r.status_code} {r.reason}")

            try:
                return base64.b64encode(r.content).decode()
            except Exception:
                raise BadRequest(f"Invalid response: {r.text}")
        except ProxyError as e:
            raise BadRequest(f"Proxy error: {e.args[0].reason}")
        except ConnectionError as e:
            raise BadRequest(f"Connection error: {e.args[0].reason}")

    # def external_license(self, method, params, web=False):
    #     entry = next(
    #         (
    #             entry
    #             for entry in config.EXTERNAL_API_BUILD_INFOS
    #             if entry["buildinfo"] == self.buildinfo
    #         ),
    #         None,
    #     )
    #     if not entry:
    #         raise BadRequest("Invalid buildinfo")
    #     api = entry["url"]
    #     payload = {"method": method, "params": params, "token": entry["token"]}
    #     r = requests.post(api, headers=self.headers, json=payload, proxies=self.proxy)
    #     if r.status_code != 200:
    #         if "message" in r.text:
    #             raise Exception(f"Error: {r.json()['message']}")
    #         raise Exception(f"Unknown Error: [{r.status_code}] {r.text}")
    #     if method == "GetChallenge":
    #         d = r.json()
    #         if entry["version"] == 2:
    #             challenge = d["message"]["challenge"]
    #             self.session_id = d["message"]["session_id"]
    #         else:
    #             challenge = d["challenge"]
    #             self.session_id = d["session_id"]
    #         if not web:
    #             return jsonify({"challenge": challenge, "session_id": self.session_id})
    #         return challenge
    #     elif method == "GetKeys":
    #         d = r.json()
    #         if entry["version"] == 2:
    #             keys = d["message"]["keys"]
    #         else:
    #             keys = d["keys"]
    #         for x in keys:
    #             kid = x["kid"]
    #             key = x["key"]
    #             self.content_keys.append(
    #                 CachedKey(
    #                     kid,
    #                     self.time,
    #                     self.user_id,
    #                     self.license_url,
    #                     "{}:{}".format(kid, key),
    #                 )
    #             )
    #     elif method == "GetKeysX":
    #         raise NotImplemented()
    #     else:
    #         raise Exception("Unknown method")

    def run(self):
        # Search for cached keys first
        if not self.force and self.kid:
            result = self.library.search(self.kid)
            if result and len(result) > 0:
                cached = self.library.search_res_to_dict(self.kid, result)
                if not self.curl and self.is_web:
                    return render_template("cache.html", results=cached)
                r = jsonify(cached)
                r.headers.add_header("X-Cache", "HIT")
                return r, 302

        if self.license_response is None:
            # Headers
            # TODO: better parsing
            try:
                self.headers = json.loads(self.headers)
            except (Exception,):
                self.headers = self.yamldomagic(self.headers)

            device = self.library.get_wvd_by_hash(self.device)
            if not device:
                raise BadRequest("WVD not found")

            cdm = wv_sessions.get(self.session_id)
            if not cdm:
                device = WidevineDevice.loads(device.wvd)
                cdm = WidevineCdm.from_device(device)

            try:
                self.session_id = cdm.open().hex()
                wv_sessions[self.session_id] = cdm
            except WidevineTooManySessions as e:
                raise InternalServerError("[Widevine] Too many open sessions, please try again in a few minutes")

            if self.server_certificate:
                try:
                    cdm.set_service_certificate(self.session_id, self.server_certificate)
                except WidevineInvalidSession as e:
                    logger.exception(e)
                    raise BadRequest("[Widevine] Invalid Session")
                except WidevineSignatureMismatch as e:
                    logger.exception(e)
                    raise BadRequest("[Widevine] Server Certificate Signature Mismatch")
                # except Exception as e:
                #     logger.exception(e)
                #     raise BadRequest("[Widevine] An error occurred")

            try:
                license_request = cdm.get_license_challenge(
                    session_id=bytes.fromhex(self.session_id),
                    pssh=self.pssh,
                    privacy_mode=True,
                )
            except WidevineInvalidInitData as e:
                logger.exception(e)
                raise BadRequest("[Widevine] Invalid init data")
            # except Exception as e:
            #     logger.exception(e)
            #     raise BadRequest("[Widevine] An error occurred")

            if self.curl or self.is_web:
                try:
                    license_response = self.post_data(self.license_url, self.headers, license_request, self.proxy)
                    cdm.parse_license(
                        session_id=bytes.fromhex(self.session_id),
                        license_message=license_response,
                    )
                except WidevineInvalidSession as e:
                    logger.exception(e)
                    raise BadRequest("[Widevine] Invalid Session")
                except WidevineInvalidLicenseMessage as e:
                    logger.exception(e)
                    raise BadRequest("[Widevine] Invalid License Message")
                # except Exception as e:
                #     logger.exception(e)
                #     raise BadRequest("[Widevine] An error occurred")

                try:
                    keys = cdm.get_keys(session_id=bytes.fromhex(self.session_id), type_="CONTENT")
                except ValueError as e:
                    logger.exception(e)
                    raise BadRequest("[Widevine] Failed to get keys")

                for key in keys:
                    self.content_keys.append(
                        CachedKey(
                            key.kid.hex,
                            self.time,
                            self.user_id,
                            self.license_url,
                            key.key.hex(),
                        )
                    )

                # caching
                data = self._cache_keys()
                data["device"] = self.device
                data["security_level"] = f"L{cdm.security_level}"

                # close the session
                cdm.close(session_id=bytes.fromhex(self.session_id))

                if self.curl:
                    return jsonify(data)

                return render_template("success.html", page_title="Success", results=data)
            else:
                return jsonify(
                    {
                        "challenge": base64.b64encode(license_request).decode(),
                        "session_id": self.session_id,
                        "device": self.device,
                        "security_level": f"L{cdm.security_level}",
                    }
                )
        else:
            # get session
            cdm = wv_sessions.get(self.session_id)
            if not cdm:
                raise BadRequest("Session not found, did you generate a challenge first?")

            try:
                cdm.parse_license(
                    session_id=bytes.fromhex(self.session_id),
                    license_message=self.license_response,
                )
            except WidevineInvalidLicenseMessage as e:
                logger.exception(e)
                raise BadRequest("[Widevine] Invalid License Message")
            except WidevineInvalidSession as e:
                logger.exception(e)
                raise BadRequest("[Widevine] Invalid Session")
            # except Exception as e:
            #     logger.exception(e)
            #     raise BadRequest("[Widevine] Exception: " + str(e))

            try:
                keys = cdm.get_keys(session_id=bytes.fromhex(self.session_id), type_="CONTENT")
            except WidevineInvalidSession as e:
                logger.exception(e)
                raise BadRequest("[Widevine] Invalid Session")
            except ValueError as e:
                logger.exception(e)
                raise BadRequest("[Widevine] Failed to get keys")

            for key in keys:
                self.content_keys.append(
                    CachedKey(
                        key.kid.hex,
                        self.time,
                        self.user_id,
                        self.license_url,
                        key.key.hex(),
                    )
                )

            # caching
            output = self._cache_keys()
            output["device"] = self.device
            output["security_level"] = f"L{cdm.security_level}"

            # close the session
            cdm.close(session_id=bytes.fromhex(self.session_id))

            return jsonify(output)

    def _cache_keys(self):
        self.library.cache_keys(self.content_keys)

        results = {
            "kid": self.kid,
            "keys": list(),
            "device": self.device,
            "session_id": self.session_id,
        }
        for key in self.content_keys:
            if key.license_url:
                s = urlsplit(key.license_url)
                license_url = "{}://{}".format(s.scheme, s.netloc)
            results["keys"].append(
                {
                    "added_at": key.added_at,
                    # We shouldnt return the license url as that could have sensitive information it in still
                    "license_url": license_url,
                    "key": f"{key.kid}:{key.key}",
                }
            )

        return results
