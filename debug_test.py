"""Debug script to test object permissions."""
import sys
sys.path.insert(0, 'tests')
sys.path.insert(0, 'src')

from conftest import generate_jwt_token, test_key as create_test_key
from jwcrypto import jwk
import json

# Create test key
test_key = jwk.JWK.generate(kty='RSA', size=2048, kid='test-key-id')

# Generate token
token = generate_jwt_token(
    test_key,
    {"sub": "user123", "aud": "test-audience", "iss": "https://test-domain.com"},
    alg="RS256"
)

print("Token generated:", token[:100])
print("\nToken payload:")
import jwt as pyjwt
try:
    decoded = pyjwt.decode(token, options={"verify_signature": False})
    print(json.dumps(decoded, indent=2))
except Exception as e:
    print(f"Error decoding: {e}")
