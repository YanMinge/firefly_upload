# Introduction(简介)
makeblock files upload tool

# How to use(使用方法）
## The environment you need(所需要的环境)

- python2 or python3
- You need to install the pyserial library, it is best to install with pip `pip install pyserial`.(你需要安装 pyserial 的库，最好是用 pip 安装 `python install pyserial`)
- You need to install the progressbar2 library, it is best to install with pip `pip install progressbar2`.(你需要安装 progressbar2 的库，最好是用 pip 安装 `pip install progressbar2`)

## Steps for usage(使用步骤)

- In the shell, type `python firefly_upload.py -p [serial port name] -i [file path] -o [file burning path in flash]` (在shell 中输入 `python firefly_upload.py -p [串口名称] -i [文件的路径] -o [文件烧入flash的路径]`)

- Example(示例): `python firefly_upload.py -p COM5 -i C:/Users/MBENBEN/Desktop/test/main.py -o /flash/main.py`

