#!/usr/bin/env python3
"""
编程猫 (CodeMao) bcmkn 文件解密工具
====================================
解密 kn.codemao.cn 播放器加载的加密 .bcmkn 项目文件。

加密方案总结：
1. 密文以 base64 字符串形式存储在 .bcmkn 文件中
2. base64 字符串整体反转后，再做标准 base64 解码（所以开头是 ==，末尾没有padding）
3. 解码后的二进制数据 = 12字节IV + 密文 + 16字节GCM认证tag
4. 加密算法：AES-256-GCM
5. 密钥派生：
   - 密钥材料 = bytes(0x00, 0x01, 0x02, ..., 0x1e) （共31个字节，0到30）
   - 最终AES密钥 = SHA-256(密钥材料) （32字节）

用法：
    python3 bcmkn_decrypt.py <input.bcmkn> [output.json]
"""

import sys
import base64
import hashlib
import json
from Crypto.Cipher import AES


def derive_key() -> bytes:
    """派生AES-256密钥：SHA256( bytes(range(31)) )"""
    key_material = bytes(range(31))  # 0x00 ~ 0x1e，共31字节
    return hashlib.sha256(key_material).digest()


def decrypt_bcmkn(data: bytes) -> bytes:
    """解密bcmkn文件内容，返回明文JSON字节"""
    # 1. 读取base64文本
    b64_text = data.decode('utf-8').strip()

    # 2. 反转base64字符串
    reversed_b64 = b64_text[::-1]

    # 3. 标准base64解码
    raw = base64.b64decode(reversed_b64)

    # 4. 拆分IV、密文、GCM tag
    iv = raw[:12]
    ciphertext_and_tag = raw[12:]
    tag = ciphertext_and_tag[-16:]
    ciphertext = ciphertext_and_tag[:-16]

    # 5. AES-256-GCM解密
    key = derive_key()
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else input_path.rsplit('.', 1)[0] + '.decoded.json'

    with open(input_path, 'rb') as f:
        encrypted_data = f.read()

    print(f"输入文件: {input_path} ({len(encrypted_data)} bytes)")

    plaintext = decrypt_bcmkn(encrypted_data)

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    # 验证JSON有效性
    try:
        data = json.loads(plaintext)
        print(f"解密成功！输出: {output_path} ({len(plaintext)} bytes)")
        print(f"项目名: {data.get('projectName', 'N/A')}")
        print(f"场景数: {len(data.get('scenes', {}).get('scenesDict', {}))}")
    except json.JSONDecodeError:
        print(f"解密完成（非JSON格式）: {output_path} ({len(plaintext)} bytes)")


if __name__ == '__main__':
    main()
#（注：内容由AI生成）
