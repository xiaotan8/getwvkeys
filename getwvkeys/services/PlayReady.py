import base64
import json
import logging
import time
import uuid
import xml.etree.ElementTree as ET

import requests
from flask import jsonify, render_template
from pyplayready import PSSH as PlayreadyPSSH
from pyplayready import Cdm as PlayreadyCdm
from pyplayready import Device as PlayreadyDevice
from pyplayready import InvalidInitData as PlayreadyInvalidInitData
from pyplayready import InvalidLicense as PlayreadyInvalidLicense
from pyplayready import InvalidPssh as PlayreadyInvalidPssh
from pyplayready import InvalidSession as PlayreadyInvalidSession
from pyplayready import TooManySessions as PlayreadyTooManySessions
from requests.exceptions import ProxyError
from werkzeug.exceptions import BadRequest, InternalServerError

from getwvkeys.libraries import Library, pr_sessions
from getwvkeys.services.BaseService import BaseService
from getwvkeys.utils import CachedKey

logger = logging.getLogger("getwvkeys.playready")


class PlayReady(BaseService):
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
        session_id=None,
        downgrade=False,
        is_web=False,
        is_curl=False,
    ):
        super().__init__(library)
        self.library = library
        self.license_url = license_url
        self.pssh: PlayreadyPSSH = PlayreadyPSSH(pssh)
        self.kid = None
        self.headers = headers
        self.device = device_hash
        self.force = force
        self.time = int(time.time())
        self.content_keys: list[CachedKey] = list()
        self.license_request = challenge
        self.license_response = response
        self.user_id = user_id
        self.proxy = proxy
        if self.proxy and isinstance(self.proxy, str):
            self.proxy = {"http": self.proxy, "https": self.proxy}
        self.store_request = {}
        self.session_id = session_id
        self.downgrade = downgrade
        self.is_web = is_web
        self.curl = is_curl

        if pssh:
            kids = [x.read_attributes()[0] for x in self.pssh.wrm_headers]
            kid = kids[0][0].value
            decoded_kid = base64.b64decode(kid)
            self.kid = str(uuid.UUID(bytes_le=decoded_kid))

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
                ET.fromstring(r.text)
                return r.text
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

            # if is_custom_buildinfo(self.buildinfo):
            #     if not self.server_certificate:
            #         try:
            #             self.server_certificate = self.post_data(
            #                 self.license_url, self.headers, base64.b64decode("CAQ="), self.proxy
            #             )
            #         except Exception as e:
            #             raise BadRequest(
            #                 f"Failed to retrieve server certificate: {e}. Please provide a server certificate manually."
            #             )
            #     params = {
            #         "init": self.pssh,
            #         "cert": self.server_certificate,
            #         "raw": False,
            #         "licensetype": "STREAMING",
            #         "device": "api",
            #     }
            #     challenge = self.external_license("GetChallenge", params, web=True)

            #     # post challenge to license server
            #     license = self.post_data(self.license_url, self.headers, base64.b64decode(challenge), self.proxy)

            #     params = {"cdmkeyresponse": license, "session_id": self.session_id}
            #     self.external_license("GetKeys", params=params, web=True)

            #     # caching
            #     data = self._cache_keys()
            #     if curl:
            #         return jsonify(data)
            #     return render_template("success.html", page_title="Success", results=data)

            device = self.library.get_prd_by_hash(self.device)
            if not device:
                raise BadRequest("PRD not found")

            cdm = pr_sessions.get(self.session_id)
            if not cdm:
                device = PlayreadyDevice.loads(device.prd)
                cdm = PlayreadyCdm.from_device(device)

            try:
                self.session_id = cdm.open().hex()
                pr_sessions[self.session_id] = cdm
            except PlayreadyTooManySessions as e:
                raise InternalServerError("[PlayReady] Too many open sessions, please try again in a few minutes")

            try:
                license_request = cdm.get_license_challenge(
                    session_id=bytes.fromhex(self.session_id), wrm_header=self.pssh.wrm_headers[0]
                )
            except PlayreadyInvalidInitData as e:
                logger.exception(e)
                raise BadRequest("[PlayReady] Invalid init data")
            except Exception as e:
                logger.exception(e)
                raise BadRequest("[PlayReady] Exception: " + str(e))

            if self.curl or self.is_web:
                try:
                    license_response = self.post_data(self.license_url, self.headers, license_request, self.proxy)
                    cdm.parse_license(
                        session_id=bytes.fromhex(self.session_id),
                        licence=license_response,
                    )
                except PlayreadyInvalidSession as e:
                    logger.exception(e)
                    raise BadRequest("[PlayReady] Invalid session")
                except PlayreadyInvalidLicense as e:
                    logger.exception(e)
                    raise BadRequest("[PlayReady] Invalid License")
                except Exception as e:
                    logger.exception(e)
                    raise BadRequest("[PlayReady] Exception: " + str(e))

                try:
                    keys = cdm.get_keys(session_id=bytes.fromhex(self.session_id))
                except ValueError as e:
                    logger.exception(e)
                    raise BadRequest("[PlayReady] Failed to get keys")

                for key in keys:
                    self.content_keys.append(
                        CachedKey(
                            key.key_id.hex,
                            self.time,
                            self.user_id,
                            self.license_url,
                            key.key.hex(),
                        )
                    )

                # caching
                data = self._cache_keys()

                # close the session
                cdm.close(session_id=bytes.fromhex(self.session_id))

                if self.curl:
                    return jsonify(data)

                return render_template("success.html", page_title="Success", results=data)
            else:
                return jsonify({"challenge": license_request, "session_id": self.session_id})
        else:
            # get session
            cdm = pr_sessions.get(self.session_id)
            if not cdm:
                raise BadRequest("[PlayReady] Session not found, did you generate a challenge first?")

            try:
                cdm.parse_license(
                    session_id=bytes.fromhex(self.session_id),
                    licence=self.license_response,
                )
            except PlayreadyInvalidLicense as e:
                logger.exception(e)
                raise BadRequest("[PlayReady] Invalid license")
            except PlayreadyInvalidSession as e:
                logger.exception(e)
                raise BadRequest("[PlayReady] Invalid session")
            except Exception as e:
                logger.exception(e)
                raise BadRequest("[PlayReady] Exception: " + str(e))

            try:
                keys = cdm.get_keys(session_id=bytes.fromhex(self.session_id))
            except PlayreadyInvalidSession as e:
                logger.exception(e)
                raise BadRequest("[PlayReady] Invalid session")
            except ValueError as e:
                logger.exception(e)
                raise BadRequest("[PlayReady] Failed to get keys")

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

            # close the session
            cdm.close(session_id=bytes.fromhex(self.session_id))

            return jsonify(output)

    def _cache_keys(self):
        self.library.cache_keys(self.content_keys)

        results = {
            "license_url": self.license_url,
            "added_at": self.time,
            "kid": self.kid,
            "keys": list(),
            "session_id": self.session_id,
        }
        for key in self.content_keys:
            # s = urlsplit(self.license_url)
            # license_url = "{}//{}".format(s.scheme, s.netloc)
            results["keys"].append(f"{key.kid}:{key.key}")

        return results
        return results
