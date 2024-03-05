# -*- coding: utf-8 -*-
import wx
from Crypto.Hash import SHA1
from Crypto.Cipher import AES, Blowfish
from Crypto.Util import strxor, Padding
from re import match as re_match
from pyperclip import copy as cp

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

class Frame(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, None, title='Navicat密码工具', size=(600, 450),name='frame',style=541072384)
        self.window = wx.Panel(self)
        self.SetBackgroundColour( wx.Colour( 255, 255, 255 ) )
        self.Centre()
        icon = wx.Icon(R'D:\Desktop\mypython\navicatdpass\navicat32.ico', wx.BITMAP_TYPE_ICO)
        self.SetIcon(icon)

        self.label5 = wx.StaticText(self.window,size=(280, 30),pos=(160, 20),label='Navicat密码加密/解密工具',name='staticText5',style=2321)
        label5_font = wx.Font(16,74,90,700,False,'Microsoft YaHei UI',28)
        self.label5.SetFont(label5_font)
        self.label5.SetForegroundColour((0, 64, 64, 255))

        self.label1 = wx.StaticText(self.window,size=(150, 30),pos=(20, 60),label='选择加密版本：',name='staticText1',style=2321)
        label1_font = wx.Font(14,74,90,400,False,'Microsoft YaHei UI',28)
        self.label1.SetFont(label1_font)
        self.combobox1 = wx.ComboBox(self.window,value='',pos=(170, 60),name='comboBox',choices=['11', '12'],style=16)
        self.combobox1.SetSize((100, 30))
        combobox1_font = wx.Font(14,74,90,400,False,'Microsoft YaHei UI',28)
        self.combobox1.SetFont(combobox1_font)

        self.label5 = wx.StaticText(self.window,size=(150, 30),pos=(300, 60),label='加密或解密：',name='staticText1',style=2321)
        label5_font = wx.Font(14,74,90,400,False,'Microsoft YaHei UI',28)
        self.label5.SetFont(label1_font)
        self.combobox2 = wx.ComboBox(self.window,value='',pos=(450, 60),name='comboBox',choices=['加密', '解密'],style=16)
        self.combobox2.SetSize((100, 30))
        combobox2_font = wx.Font(14,74,90,400,False,'Microsoft YaHei UI',28)
        self.combobox2.SetFont(combobox2_font)

        self.label3 = wx.StaticText(self.window,size=(124, 30),pos=(25, 90),label='密码字符串：',name='staticText3',style=2321)
        label3_font = wx.Font(14,74,90,400,False,'Microsoft YaHei UI',28)
        self.label3.SetFont(label3_font)
        self.textctrl1 = wx.TextCtrl(self.window,size=(533, 30),pos=(25, 120),value='',name='text',style=0)
        textctrl1_font = wx.Font(10,74,90,400,False,'Microsoft YaHei UI',28)
        self.textctrl1.SetFont(textctrl1_font)
        self.textctrl1.SetHint("请输入密码字符串...")

        self.button1 = wx.Button(self.window,size=(90, 30),pos=(120, 160),label='执 行',name='button1')
        button1_font = wx.Font(12,74,90,400,False,'Microsoft YaHei UI',28)
        self.button1.SetFont(button1_font)
        self.button1.Bind(wx.EVT_LEFT_DOWN,self.button1_down)
        self.button2 = wx.Button(self.window,size=(90, 30),pos=(240, 160),label='清 除',name='button2')
        button2_font = wx.Font(12,74,90,400,False,'Microsoft YaHei UI',28)
        self.button2.SetFont(button2_font)
        self.button2.Bind(wx.EVT_LEFT_DOWN,self.button2_down)
        self.button3 = wx.Button(self.window,size=(126, 30),pos=(360, 160),label='帮 助',name='button3')
        button3_font = wx.Font(12,74,90,400,False,'Microsoft YaHei UI',28)
        self.button3.SetFont(button3_font)
        self.button3.Bind(wx.EVT_LEFT_DOWN,self.button3_down)

        self.text_ctrl1 = wx.TextCtrl(self.window,size=(540, 130),pos=(25, 220),style=wx.TE_READONLY | wx.TE_MULTILINE | wx.TE_CENTER | wx.TE_WORDWRAP|wx.NO_BORDER|wx.TE_MULTILINE|wx.TE_NO_VSCROLL)
        self.text_ctrl1.SetBackgroundColour(wx.Colour(240,240,240))
        self.text_ctrl1.Hide()
        self.text_ctrl = wx.TextCtrl(self.window, size=(540, 190), pos=(25, 200),style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_WORDWRAP|wx.NO_BORDER)
        self.text_ctrl.SetBackgroundColour(wx.Colour(240,240,240))
        self.text_ctrl.Hide()

    def button1_down(self,event):
        if self.combobox1.GetValue()=="" or self.combobox2.GetValue()=="" or self.textctrl1.GetValue()=="":
            display_text="请将上方信息填写完整！"
            text_ctrl1_font = wx.Font(14,74,90,400,False,'Microsoft YaHei UI',30)
            self.text_ctrl1.SetFont(text_ctrl1_font)
            self.text_ctrl1.SetForegroundColour((255, 0, 0, 255))
            self.text_ctrl1.SetBackgroundColour((255,255,255))
            self.text_ctrl1.SetLabelText(display_text)
            self.text_ctrl.Hide()
            self.text_ctrl1.Show()
            return
        else:
            version = int(self.combobox1.GetValue())
            passtpye = self.combobox2.GetValue()
            decode_string = str(self.textctrl1.GetValue())

        if version==11 and passtpye=="加密":
            code_pw=Navicat11Crypto().EncryptString(decode_string)
        elif version==11 and passtpye=="解密":
            if not myApp.ishex(decode_string):
                wx.MessageBox("加密的字符串不正确！", "提示",wx.OK | wx.ICON_INFORMATION)
                return
            code_pw=Navicat11Crypto().DecryptString(decode_string)
        elif version==12 and passtpye=="加密":
            code_pw=Navicat12Crypto().EncryptStringForNCX(decode_string)
        elif version==12 and passtpye=="解密":
            if not myApp.ishex(decode_string):
                wx.MessageBox("加密的字符串不正确！", "提示",wx.OK | wx.ICON_INFORMATION)
                return
            code_pw=Navicat12Crypto().DecryptStringForNCX(decode_string)
        display_text="原始密码为: "+ code_pw
        text_ctrl1_font = wx.Font(14,74,700,400,False,'Microsoft YaHei UI',30)
        self.text_ctrl1.SetFont(text_ctrl1_font)
        self.text_ctrl1.SetForegroundColour((255, 0, 0, 255))
        self.text_ctrl1.SetBackgroundColour((255,255,255))
        self.text_ctrl1.SetLabelText(display_text)
        self.text_ctrl.Hide()
        self.text_ctrl1.Show()
        cp(code_pw)
        wx.MessageBox("密码已复制到剪贴板！", "提示",wx.OK | wx.ICON_INFORMATION)

    def button2_down(self,event):
        self.combobox1.SetValue('')
        self.combobox1.SetSelection(wx.NOT_FOUND)
        self.combobox2.SetValue('')
        self.combobox2.SetSelection(wx.NOT_FOUND)
        self.textctrl1.SetValue('')
        self.text_ctrl1.SetLabelText('')
        self.text_ctrl1.Hide()
        self.text_ctrl.Hide()

    def button3_down(self,event):
        self.text_ctrl1.Hide()
        if self.text_ctrl.IsShown():
            self.text_ctrl.Hide()
        else:
            text = '''加密密码字符串查找方法：
一、注册表查找密码，加密版本为11：
1、打开注册表并找到HCU\\SOFTWARE\PremiumSoft\\Navicat\\Servers
2、点击相应的服务器，在右边窗口中找到字符串键Pwd，双击此键
3、在出现的窗口中，“数值数据”下方的框中即为使用11版本加密的密码。
二、从软件导出密码，加密版本为12：
1、点击软件的“文件”——“导出连接”
2、勾选下方的“导出密码”，导出.ncx连接文件
3、用文本编辑器打开导出的.ncx文件，找到服务器对应的Password，等号后面的字符串即为使用12版本加密的密码。
作者：飘风剑，qq：12315557，邮箱：whhlcj@163.com
'''
            self.text_ctrl.SetForegroundColour((0, 64, 64, 255))
            self.text_ctrl.SetValue(text)
            self.text_ctrl.Show()

class myApp(wx.App):
    @staticmethod
    def ishex(s):
        t=r"^(0x|0X)?[a-fA-F0-9]+$"
        if re_match(t, s):
            return True
        else:
            return False
    def  OnInit(self):
        self.frame = Frame()
        self.frame.Show(True)
        return True

if __name__ == '__main__':
    app = myApp()
    app.MainLoop()