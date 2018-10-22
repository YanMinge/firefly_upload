# firefly_upload
makeblock files upload tool

# 使用方法
## 所需要的环境

- python 2.7
- 需要安装 pyserial 的库，最好是用 pip 安装 `python install pyserial`
- 需要安装 progressbar2 的库，最好是用 pip 安装 `pip install progressbar2`

## 使用步骤

- 在shell 中输入 `python firefly_upload.py -p [串口名称] -i [文件的路径]` -o[文件烧入flash的路径]

- 示例: `python firefly_upload.py -p COM5 -i C:/Users/MBENBEN/Desktop/烧录python/main.py -o /flash/main.py`
