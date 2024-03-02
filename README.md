# navicat_pass_decrypt
### navicat密码加密和解密工具
#### 说明：
* 1、加密和解密算法参考了github，修改了识别编码，支持除ascii以外的编码
* 2、fromcmd.py为cmd运行工具，
* 3、fromgui.py为带界面的工具
* 4、程序可以通过pyinstaller编译：
  pyinstaller -Fc -i dos64.ico --onefile fromcmd.py
  pyinstaller -Fw -i favicon64.ico --onefile fromgui.py
* 5、也可以通过nuitka编译：
  python -m nuitka --onefile --windows-icon-from-ico=favicon64.ico --disable-console fromgui.py


#### 参考：https://github.com/HyperSine/how-does-navicat-encrypt-password
