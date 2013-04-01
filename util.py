import hashlib
import string

from django.conf import settings


def generate_sso_token(id, timestamp):
    token = "%s%s%s" % (id, timestamp, settings.SSO_SECRET)
    md5 = hashlib.md5()
    md5.update(token)
    if settings.SSO_CAPS:
        return string.upper(md5.hexdigest())
    else:
        return md5.hexdigest()
