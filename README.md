# PleaseOneScan
人人有饭吃，人人有扫描器，每个安服仔都能上手改装的扫描器

python3 main.py

![image](https://github.com/idssgmcc/PleaseOneScan/assets/47582299/c73ee971-dd94-4367-acbd-35ae9383fe75)


如果你要增加新的PoC（Proof of Concept）到你的漏洞扫描器中，你需要修改以下几个地方：

      创建新的PoC脚本文件：在vulnerability_scanners目录下创建新的PoC脚本文件。
      修改__init__.py文件：在vulnerability_scanners目录下的__init__.py文件中导入新的PoC函数。
      修改主GUI应用：在主GUI应用中添加新的PoC选项，并调用相应的检测函数。
      修改spec文件（如果你使用PyInstaller打包）：在spec文件中添加新的PoC模块到hiddenimports列表中。

1. 修改__init__.py文件
在vulnerability_scanners目录下的__init__.py文件中导入新的PoC函数：

2. 修改主GUI应用
在主GUI应用中添加新的PoC选项，并调用相应的检测函数。

<h1>导入POC</h1>
from vulnerability_scanners.starrocks import check_starrocks

....

self.script_options = [

  "New PoC"  # 新添加的选项

]
....

<h1>调用相应的漏洞检测函数</h1>
        try:
            result = ""
            
            elif script == "New PoC":  # 新添加的检测函数调用
                result = check_new_poc(url)
            self.result_text.insert(tk.END, result)
