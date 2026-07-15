import json
import binascii
import urllib.parse
import random
import base64
import sys
import re
import requests
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA

RSA_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgF21fulwAZs3l6ru8M2f
LPDO9Y4+0zOF0Dblz7nOmrGYGDIpcPwegNYLvpQrcFq2YjfCzVF+n1xd+k8hiYxd
wggp9oiB9UCN4MLr+qOZXtWKxBJDQAOn3w+tu0SwGwKsONI+CDGtF5l5yfjAunTY
wLduc3aqZjPmo2UXbGdGqrGbxPS5lY3/kZykce+i+txO7vYfJevHYyg5eaOGfpjN
8/666L60mv+Xpqd272c3VcbjbYW5ZJCljhZnHR+cPeAyn6P5encb0afQhoyz0LnA
RiRP51C9Nv4avG/RbGgD2o4asbaEXJ6zPgDxRE4e34EkhGM46XcmmJeQSA54LSJ4
3QIDAQAB
-----END PUBLIC KEY-----"""

AES_IV = b"16-Bytes--String"
BASE = "https://userappeal.vivo.com.cn"


def _rand_key():
    return ''.join(random.choice("0123456789abcdef") for _ in range(16))


def _rsa_b64(plaintext: str) -> str:
    ct = PKCS1_v1_5.new(RSA.import_key(RSA_PEM)).encrypt(plaintext.encode())
    return base64.b64encode(ct).decode()


def _aes_enc(plaintext: str, key: str) -> str:
    ct = AES.new(key.encode(), AES.MODE_CBC, AES_IV).encrypt(
        pad(plaintext.encode(), 16, 'pkcs7'))
    return binascii.hexlify(ct).decode()


def _aes_dec(ct_hex: str, key: str) -> str:
    pt = unpad(AES.new(key.encode(), AES.MODE_CBC, AES_IV).decrypt(
        binascii.unhexlify(ct_hex)), 16, 'pkcs7')
    return pt.decode()


def _serialize(params: dict) -> str:
    return "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in params.items())


def enc_req(params: dict):
    aes_key = _rand_key()
    enc_key = _rsa_b64(aes_key)
    enc_data = _aes_enc(_serialize(params), aes_key)
    return {"encData": enc_data, "encKey": enc_key, "encVer": "1_1_2"}, aes_key


def dec_resp(text: str, aes_key: str) -> dict:
    if text.startswith("enc:"):
        return json.loads(_aes_dec(text[4:], aes_key))
    return json.loads(text)


class Vivo:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Mobile Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8;",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": BASE,
            "Referer": BASE + "/",
        })
        self.rc = ""

    def _post(self, path, params, timeout=30):
        body, key = enc_req(params)
        r = self.s.post(BASE + path, data=body, timeout=timeout)
        return dec_resp(r.text, key)

    def _get_enc(self, path, params, timeout=30):
        body, key = enc_req(params)
        r = self.s.get(BASE + path, params=body, timeout=timeout)
        return dec_resp(r.text, key)

    def init(self):
        self.s.get(BASE + "/", timeout=30)
        return True

    def get_history(self, phone, ac="86"):
        d = self._post("/userappeal/v3/getHistoryAccount",
                       {"phoneAreaCode": ac, "account": phone, "e": 3})
        data = d.get("data", {})
        if isinstance(data, dict) and data.get("randomCode"):
            self.rc = data["randomCode"]
        return d

    def get_slider(self, phone, ac="86"):
        d = self._get_enc("/userappeal/v1/getSliderUrl", {
            "sliderVersionType": 2, "clientType": 2,
            "scene": "fillAccount",
            "phoneAreaCode": ac, "account": phone, "e": 3,
        })
        if d.get("code") in ("0", 0):
            self.rc = d.get("randomCode", self.rc)
        return d

    def check_user(self, phone, ac="86", pic_code="", account_type=2):
        return self._post("/userappeal/v3/checkUser", {
            "phoneAreaCode": ac, "account": phone,
            "picCode": pic_code,
            "randomCode": self.rc if not pic_code else "",
            "accountType": account_type, "e": 3,
        })

    def get_account_info(self, phone, ac="86"):
        try:
            self.init()
            
            # 获取历史账号信息
            history_result = self.get_history(phone, ac)
            
            # 获取滑块验证
            slider_result = self.get_slider(phone, ac)
            
            # 检查是否需要滑块验证
            if slider_result.get('code') == "10001":
                return {"need_slider": True, "message": "需要滑块验证"}
            
            # 检查用户
            check_result = self.check_user(phone, ac)
            
            # 检查是否需要验证码
            if check_result.get('code') == "10001":
                return {"need_captcha": True, "message": "需要图形验证码"}
            
            return {"success": True, "data": check_result}
            
        except Exception as e:
            return {"success": False, "error": str(e)}

print(f"{Fore.CYAN}{Style.BRIGHT}官方频道 - @Jay_Chou_fenxiang \n{Style.RESET_ALL}")
def main():
    phone = input("请输入要查询的手机号: ").strip()
    
    if not re.match(r'1[3-9]\d{9}$', phone):
        print("❌ 手机号格式不正确")
        return
    
    vivo = Vivo()
    result = vivo.get_account_info(phone)
    
    # 处理滑块验证
    if result.get("need_slider"):
        print("\n⚠️ 需要滑块验证！请关闭WiFi网络，切换至移动网络后重试")
        return
    
    # 处理图形验证码
    if result.get("need_captcha"):
        print("\n⚠️ 需要图形验证码验证，请关闭WiFi网络，切换至移动网络后重试")
        return
    
    # 处理错误
    if not result.get("success"):
        print(f"\n❌ 查询失败: {result.get('error', '未知错误')}")
        return
    
    # 解析账号信息
    data = result.get("data", {})
    if data.get('code') != "0":
        print("\n❌ 账号不存在")
        if data.get('msg'):
            print(f"提示: {data['msg']}")
        return
    
    user = data.get('data', {}).get('userInfoList', [{}])[0]
    
    # 优化显示格式
    print(f"\n账号: {user.get('nickName', '无')}")
    print(f"邮箱: {user.get('bindEmail', '无')}")
    print(f"手机: {user.get('bindPhone', '无')}")
    print(f"实名: {user.get('realNameInfo', '无')}")
    print(f"OpenID: {user.get('openid', '无')}")


if __name__ == "__main__":
    main()