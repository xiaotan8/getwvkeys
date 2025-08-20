import yaml
from werkzeug.exceptions import BadRequest

from getwvkeys.libraries import Library


class BaseService:
    def __init__(self, library: Library):
        self.library = library

    @staticmethod
    def yamldomagic(headers):
        try:
            return (
                {
                    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (Ktesttemp, like Gecko) "
                    "Chrome/90.0.4430.85 Safari/537.36"
                }
                if headers == ""
                else yaml.safe_load(headers)
            )
        except Exception as e:
            raise BadRequest(f"Wrong headers: {str(e)}")
