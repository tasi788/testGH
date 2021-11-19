
import logging
import os

import sys
from base64 import b64encode
from datetime import datetime

import requests
# from fake_useragent import UserAgent
from nacl import encoding, public



logger = logging.getLogger(__name__)
logging.basicConfig(level='INFO',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

GH_REPO = os.getenv('GH_REPO')
GH_TOKEN = os.getenv('GH_TOKEN')



def update_secret(keys: str, value: str):
    base_url = f'https://api.github.com/repos/{GH_REPO}/actions/secrets'
    headers = {'Accept': 'application/vnd.github.v3+json', 'Authorization': f'token {GH_TOKEN}'}
    resp = requests.get(base_url + '/public-key', headers=headers)
    if 'key' not in resp.json():
        logger.critical('讀取 GH 公鑰失敗')
        sys.exit(1)
    public_key = resp.json()['key']
    key_id = resp.json()['key_id']

    public_key = public.PublicKey(public_key.encode('utf-8'), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = b64encode(
        sealed_box.encrypt(value.encode('utf-8'))).decode('utf-8')

    data = {'encrypted_value': encrypted, 'key_id': key_id}
    resp = requests.put(
        base_url + f'/{keys}',
        headers=headers,
        json=data)
    if resp.status_code in [201, 204]:
        logger.info('上傳 SECRET 成功')
    else:
        logger.critical('上傳 SECRET 失敗。')


def testkey():
    update_secret('meow', str(datetime.now()))
    pass

if __name__ == '__main__':
    testkey()
