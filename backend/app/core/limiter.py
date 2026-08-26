from slowapi import Limiter
from slowapi.util import get_remote_address

# Shared rate limiter instance for public demo routes
limiter = Limiter(key_func=get_remote_address)
