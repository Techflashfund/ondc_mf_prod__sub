import os
import base64
import json
import nacl.public
import requests
from datetime import datetime, timedelta
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .cryptic_utils import decrypt
from django.views.decorators.csrf import csrf_exempt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status


# Load from environment variables
SIGNED_UNIQUE_REQ_ID = os.environ.get("SIGNED_UNIQUE_REQ_ID")
ENCRYPTION_PRIVATE_KEY_BASE64 = os.environ.get("Encryption_Privatekey")

# ONDC's Production Public Key (constant)
ONDC_PUBLIC_KEY_BASE64="MCowBQYDK2VuAyEAvVEyZY91O2yV8w8/CAwVDAnqIZDJJUPdLUUKwLo3K0M="

def ondc_site_verification(request):
    return HttpResponse(f"""
    <html>
        <head>
            <meta name='ondc-site-verification' content='o2XaabS3UVHo84J1zY2C0RtKRja9pHfnkbRCU8h55Z5laWCWSY6PeuS3SDoBpNvL0yFlcYAJ3JFyutGVx7jsDQ==' />
        </head>
        <body>
            ONDC Site Verification Page
        </body>
    </html>
    """, content_type="text/html")


def decrypt_challenge(encrypted_challenge, shared_key):
    cipher = AES.new(shared_key, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted_challenge))
    return unpad(decrypted_bytes, AES.block_size).decode('utf-8')

@csrf_exempt
def on_subscribe(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            encrypted_challenge = data.get("challenge")

            # Load encryption private key (correct way)
            encryption_private_key_base64 = os.getenv("Encryption_Privatekey")
            encryption_private_key_bytes = base64.b64decode(encryption_private_key_base64)

            private_key = serialization.load_der_private_key(
                encryption_private_key_bytes,
                password=None
            )

            # Load ONDC public key
            ondc_public_key_bytes = base64.b64decode(ONDC_PUBLIC_KEY_BASE64)
            public_key = serialization.load_der_public_key(ondc_public_key_bytes)

            # Generate shared key
            shared_key = private_key.exchange(public_key)

            # Decrypt the challenge
            decrypted_challenge = decrypt_challenge(encrypted_challenge, shared_key)

            return JsonResponse({"answer": decrypted_challenge})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)


@api_view(['POST'])
def subscribe(request):
    try:
        input_data = request.data
        current_timestamp = datetime.utcnow()
        valid_until = current_timestamp.replace(year=current_timestamp.year + 2)

        entity = input_data.get('message', {}).get('entity', {})
        key_pair = entity.get('key_pair', {})

        data = {
            "context": {
                "operation": {
                    "ops_no": input_data.get('context', {}).get('operation', {}).get('ops_no')
                }
            },
            "message": {
                "request_id": os.getenv('REQUEST_ID'),
                "timestamp": current_timestamp.isoformat() + 'Z',
                "entity": {
                    "gst": {
                        "legal_entity_name": entity.get('gst', {}).get('legal_entity_name', "ABC Incorporates"),
                        "business_address": entity.get('gst', {}).get('business_address', "Trade World, Mansarpur, Coorg, Karnataka 333333"),
                        "city_code": entity.get('gst', {}).get('city_code', ["std:080"]),
                        "gst_no": entity.get('gst', {}).get('gst_no', "07AAACN2082N4Z7")
                    },
                    "pan": {
                        "name_as_per_pan": entity.get('pan', {}).get('name_as_per_pan', "ABC Incorporates"),
                        "pan_no": entity.get('pan', {}).get('pan_no', "ASDFP7657Q"),
                        "date_of_incorporation": entity.get('pan', {}).get('date_of_incorporation', "23/06/1982")
                    },
                    "name_of_authorised_signatory": entity.get('name_of_authorised_signatory', "Anand Sharma"),
                    "address_of_authorised_signatory": entity.get('address_of_authorised_signatory', "405, Pinnacle House, Kandiwali, Mumbai 400001"),
                    "email_id": entity.get('email_id', "anand.sharma@abc.com"),
                    "mobile_no": entity.get('mobile_no', 9912332199),
                    "country": entity.get('country', "IND"),
                    "subscriber_id": entity.get('subscriber_id'),
                    "unique_key_id": entity.get('unique_key_id', "UK-KEY999"),
                    "callback_url": entity.get('callback_url', "/"),
                    "key_pair": {
                        "signing_public_key": os.getenv('SIGNING_PUBLIC_KEY'),
                        "encryption_public_key": os.getenv('ENCRYPTION_PUBLIC_KEY'),
                        "valid_from": key_pair.get('valid_from', current_timestamp.isoformat() + 'Z'),
                        "valid_until": key_pair.get('valid_until', valid_until.isoformat() + 'Z'),
                    }
                },
                "network_participant": input_data.get('message', {}).get('network_participant')
            }
        }

        environment_link = os.getenv('ENVIRONMENT_LINK')
        if not environment_link:
            return Response({"message": "Environment link not configured"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = requests.post(f"{environment_link}/subscribe", json=data)

        if response.status_code == 200 and not response.json().get('error'):
            return Response({"message": "success"}, status=status.HTTP_200_OK)
        else:
            return Response(response.json(), status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        print(str(e))
        return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
