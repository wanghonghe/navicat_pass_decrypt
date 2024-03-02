from Crypto.Hash import SHA1
from Crypto.Cipher import AES, Blowfish
from Crypto.Util import strxor, Padding

class Navicat11Crypto:
    def __init__(self, Key = b'3DC5CA39'):
        self._Key = SHA1.new(Key).digest()
        self._Cipher = Blowfish.new(self._Key, Blowfish.MODE_ECB)
        self._IV = self._Cipher.encrypt(b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF')

    def EncryptString(self, s : str):
        if type(s) != str:
            raise TypeError('Parameter s must be a str.')
        else:
            plaintext = s.encode('utf-8')
            ciphertext = b''
            cv = self._IV
            full_round, left_length = divmod(len(plaintext), 8)

            for i in range(0, full_round * 8, 8):
                t = strxor.strxor(plaintext[i:i + 8], cv)
                t = self._Cipher.encrypt(t)
                cv = strxor.strxor(cv, t)
                ciphertext += t
            
            if left_length != 0:
                cv = self._Cipher.encrypt(cv)
                ciphertext += strxor.strxor(plaintext[8 * full_round:], cv[:left_length])

            return ciphertext.hex().upper()

    def DecryptString(self, s : str):
        if type(s) != str:
            raise TypeError('Parameter s must be str.')
        else:
            plaintext = b''
            ciphertext = bytes.fromhex(s)
            cv = self._IV
            full_round, left_length = divmod(len(ciphertext), 8)

            for i in range(0, full_round * 8, 8):
                t = self._Cipher.decrypt(ciphertext[i:i + 8])
                t = strxor.strxor(t, cv)
                plaintext += t
                cv = strxor.strxor(cv, ciphertext[i:i + 8])
            
            if left_length != 0:
                cv = self._Cipher.encrypt(cv)
                plaintext += strxor.strxor(ciphertext[8 * full_round:], cv[:left_length])
            
            return plaintext.decode('utf-8')

class Navicat12Crypto(Navicat11Crypto):

    def __init__(self):
        super().__init__()

    def EncryptStringForNCX(self, s : str):
        cipher = AES.new(b'libcckeylibcckey', AES.MODE_CBC, iv = b'libcciv libcciv ')
        padded_plaintext = Padding.pad(s.encode('utf-8'), AES.block_size, style = 'pkcs7')
        return cipher.encrypt(padded_plaintext).hex().upper()

    def DecryptStringForNCX(self, s : str):
        cipher = AES.new(b'libcckeylibcckey', AES.MODE_CBC, iv = b'libcciv libcciv ')
        padded_plaintext = cipher.decrypt(bytes.fromhex(s))
        return Padding.unpad(padded_plaintext, AES.block_size, style = 'pkcs7').decode('utf-8')

print("帮助信息:")
print("注册表导出密码，加密版本为11：")
print(R"1、打开注册表并找到HCU\SOFTWARE\PremiumSoft\Navicat\Servers")
print("2、点击相应的服务器，在右边窗口中找到字符串键Pwd，双击此键")
print("3、在出现的窗口中，“数值数据”下方的框中即为使用11版本加密的密码。")
print("从软件导出密码，加密版本为12：")
print("1、点击软件的“文件”——“导出连接”")
print("2、选择导出的服务器并勾选下方的“到处密码”，导出.ncx连接文件")
print("3、使用文本编辑器打开导出的.ncx文件，找到服务器对应的password字段后面的字符串即为使用12版本加密的密码。")
input("按任意键继续...")

while True:
    print("请选择加密方式:")
    print("1. 注册表导出的密码加密方式为11")
    print("2. 软件导出的密码加密方式为12")
    choice_version = input()
    if choice_version == "1":
        version = 11
        break
    elif choice_version == "2":
        version = 12
        break
    else:
        print("输入错误！")
while True:
    print("请选择加密或解密:")
    print("1. 加密")
    print("2. 解密")
    choice_passway = input()
    if choice_passway == "1":
        passway = 1
        break
    elif choice_passway == "2":
        passway = 2
        break
    else:
        print("输入错误！")
while True:
    string = input("请输入加密或解密的字符串：")
    if string == "":
        print("密码输入错误，请重新输入！")
    else:
        break

if version == 11 and passway == 1:
    print(Navicat11Crypto().EncryptString(string))
elif version == 11 and passway == 2:
    print(Navicat11Crypto().DecryptString(string))
elif version == 12 and passway == 1:
    print(Navicat12Crypto().EncryptStringForNCX(string))
elif version == 12 and passway == 2:
    print(Navicat12Crypto().DecryptStringForNCX(string))
else:
    print("输入错误！")
print("按任意键退出...")
input()
