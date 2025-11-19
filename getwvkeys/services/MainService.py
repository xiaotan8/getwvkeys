from getwvkeys.services.PlayReady import PlayReady
from getwvkeys.services.Widevine import Widevine


class MainService:
    @staticmethod
    def main(**kwargs):
        library = kwargs.pop("library")
        device_hash = kwargs.pop("device_hash")

        d = library.get_prd_by_hash(device_hash)
        if d:
            print("Detected a PlayReady device")
            to_pop = [
                "server_certificate",
                "disable_privacy",
            ]
            for key in to_pop:
                kwargs.pop(key, None)
            return PlayReady(library=library, device_hash=device_hash, **kwargs)

        to_pop = [
            "downgrade",
        ]
        for key in to_pop:
            kwargs.pop(key, None)
        return Widevine(library=library, device_hash=device_hash, **kwargs)
