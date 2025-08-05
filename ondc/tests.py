import base64
from nacl.signing import SigningKey
from nacl.bindings import crypto_sign_ed25519_sk_to_seed

# Base64 encoded full private key (private+public)
private_key_base64 = "RlN6KBUkq0SWQiML4Y4jJ7y407eZsyFIGU1cZpAKiKfHTf0Ccb0CtKRbZhLw4Qv0iljcMUNNe5bVWOrdu+d9Ow=="

# The request_id you will use in payload
request_id ="adbaaa54-06c8-4fd3-95a4-528f75d51ce8" 

# Decode and get the 32 bytes seed
private_key_bytes = base64.b64decode(private_key_base64)
seed = crypto_sign_ed25519_sk_to_seed(private_key_bytes)
signing_key = SigningKey(seed)

# Sign the request_id
signed = signing_key.sign(request_id.encode())

# Base64 encode the signature
signature_base64 = base64.b64encode(signed.signature).decode()

print("SIGNED_UNIQUE_REQ_ID =", signature_base64)
