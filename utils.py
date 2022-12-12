from urllib.parse import urlencode as _urlencode
import urllib.parse as urlparse
import json
import base64
import struct
import hashlib

def to_bytes(x, charset='utf-8', errors='strict'):
    if x is None:
        return None
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return x.encode(charset, errors)
    if isinstance(x, (int, float)):
        return str(x).encode(charset, errors)
    return bytes(x)

def to_unicode(x, charset='utf-8', errors='strict'):
    if x is None or isinstance(x, str):
        return x
    if isinstance(x, bytes):
        return x.decode(charset, errors)
    return str(x)
def url_encode(params):
    encoded = []
    for k, v in params:
        encoded.append((to_bytes(k), to_bytes(v)))
    return to_unicode(_urlencode(encoded))

def add_params_to_qs(query, params):
    """Extend a query with a list of two-tuples."""
    if isinstance(params, dict):
        params = params.items()

    qs = urlparse.parse_qsl(query, keep_blank_values=True)
    qs.extend(params)
    return url_encode(qs)

def add_params_to_uri(uri, params, fragment=False):
    """Add a list of two-tuples to the uri query components."""
    sch, net, path, par, query, fra = urlparse.urlparse(uri)
    if fragment:
        fra = add_params_to_qs(fra, params)
    else:
        query = add_params_to_qs(query, params)
        print(query)
    return urlparse.urlunparse((sch, net, path, par, query, fra))