import gzip
import hashlib, base64, time, requests, Tools
from io import BytesIO

from loguru import logger

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def retdata(mingwen):
    key = bytes.fromhex("F6F472F595B511EA9237685B35A8F866")
    iv = bytes.fromhex("00000000000000000000000000000000")
    aes = AES.new(key, AES.MODE_CBC, IV=iv)
    hash = hashlib.md5(mingwen.encode()).hexdigest()
    mingwen = mingwen + "&checkcode=" + hash[-8:] + hash[8:24] + hash[:8]

    padded_data = pad(mingwen.encode(), AES.block_size)
    en_text = aes.encrypt(padded_data)
    return base64.b64encode(en_text).decode()


def retdecode(mingwen):
    key = bytes.fromhex("F6F472F595B511EA9237685B35A8F866")
    iv = bytes.fromhex("00000000000000000000000000000000")
    aes = AES.new(key, AES.MODE_CBC, IV=iv)
    ciphertext = base64.b64decode(mingwen)

    decrypted_data = aes.decrypt(ciphertext)
    plaintext_bytes = unpad(decrypted_data, AES.block_size)
    return plaintext_bytes.decode("utf-8")


def decompress(compressed_str):
    """
    解压缩 GZIP + Base64 编码的字符串

    参数:
        compressed_str (str): 压缩后的字符串

    返回:
        str: 解压缩后的原始字符串，如果解压失败返回 None
    """
    if not compressed_str:
        return None

    try:
        # Base64 解码
        compressed_bytes = base64.b64decode(compressed_str)

        # 使用 BytesIO 作为内存缓冲区
        with BytesIO(compressed_bytes) as compressed_stream:
            # GZIP 解压缩
            with gzip.GzipFile(fileobj=compressed_stream, mode='rb') as gzip_file:
                # 读取解压后的数据
                decompressed_bytes = gzip_file.read()

        # 转换为字符串（假设 UTF-8 编码）
        return decompressed_bytes.decode('utf-8')

    except Exception as e:
        print(f"解压缩失败: {e}")
        return None


logger.info(retdata(
    "mobile=19567356747&password=123123&client_id=2019041810222516127&client_secret=c5ad2a4290faa3df39683865c2e10310&state=9XhN9EDVcP&response_type=token&ostype=ios&imei=00&mac=00:00:00:00:00:00&model=Pixel 4&sdk=33&serviceTime=1754966046798&mod=Google"))


def login(mingwen):
    nonce = Tools.random_string(10)
    timestamp = int(time.time() * 1000)
    sign = f"2019041810222516127{timestamp}{nonce}c5ad2a4290faa3df39683865c2e10310a14f0be589630ff5b16d35de3b0b7190"
    signature = hashlib.md5(sign.encode()).hexdigest()
    headers = {
        "User-Agent": "okhttp/4.9.0",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "channel": "xiaomi",
        "platformNo": "Android",
        "appVersionCode": "1673",
        "version": "V8.2.9",
        "imei": "a-9649f2de5a68cca1",
        "imsi": "unknown",
        "deviceModel": "Pixel 4",
        "deviceBrand": "google",
        "deviceType": "Android",
        "accessChannel": "1",
        "oauthConsumerKey": "2019041810222516127",
        "timestamp": str(timestamp),
        "nonce": nonce,
        "signature": signature
    }
    url = "https://api.00bang.cn/llb/oauth/llb/ucenter/login"

    data = f"sd=M{retdata(mingwen)}"
    response = requests.post(url, headers=headers, data=data)

    # print(response.text)
    # print(response.json()["sd"][1:])
    reslut=retdecode(response.json()["sd"][1:])
    ret=decompress(reslut)
    logger.debug(f"结果:{ret}")
login(
    "mobile=13058906096&password=ygljl200&client_id=2019041810222516127&client_secret=c5ad2a4290faa3df39683865c2e10310&state=9XhN9EDVcP&response_type=token&ostype=ios&imei=00&mac=00:00:00:00:00:00&model=Pixel 4&sdk=33&serviceTime=1754966046798&mod=Google")




