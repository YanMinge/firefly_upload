# -*- coding: utf-8 -*
# python2
import os
import time
import threading
import sys
import serial
import serial.tools.list_ports
import getopt
import re
import random
import codecs, binascii
import progressbar

progress_bar = progressbar.ProgressBar()

time_count               = 0
COMMAND_MAX_TIME_OUT     = 20

serial_name              = None
serial_fd                = None

input_file_path          = None
target_file_path         = None
FILE_BLOCK_SIZE          = 240

failed_to_exit           = False
update_completed         = False
command_result           = False
retransmission_count     = 0

frame_header_str         = "F3"
frame_end_str            = "F4"
protocol_id_str          = "01"
dev_id_str               = "00"
srv_id_str               = "5E"
file_header_cmd_id_str   = "01"
file_block_cmd_id_str    = "02"
file_delete_str          = "03"
file_state_cmd_id_str    = "F0"
file_type_str            = "00"

FRAME_HEAD               = int(frame_header_str, 16) 
FRAME_END                = int(frame_end_str, 16)
DEV_ID                   = int(dev_id_str, 16)
SRV_ID                   = int(srv_id_str, 16)
CMD_STATE_ID             = int(file_state_cmd_id_str, 16)

FTP_FSM_HEAD_S           = 0
FTP_FSM_HEAD_CHECK_S     = 1
FTP_FSM_LEN1_S           = 2
FTP_FSM_LEN2_S           = 3
FTP_FSM_DATA_S           = 4
FTP_FSM_CHECK_S          = 5
FTP_FSM_END_S            = 6

class file_transfer_protocol_process(object):
    def __init__(self):
        self.__state = FTP_FSM_HEAD_S
        self.__buf = []
        self.__data_len = 0
        self.__cur_data_len = 0
        self.__checksum = 0x00
        self.__headchecksum = 0x00
        self.__recv_head_checksum = 0x00

    def get_state(self):
        return self.__state

    def set_state(self, s):
        self.__state = s

    def push_char(self, c):
        c = ord(c)
        if (FTP_FSM_HEAD_S == self.__state):
            if (FRAME_HEAD == c):
                self.__state = FTP_FSM_HEAD_CHECK_S
                self.__buf = []
                self.__checksum = 0
                self.__headchecksum = c

        elif (FTP_FSM_HEAD_CHECK_S == self.__state):
            self.__recv_head_checksum = c
            self.__state = FTP_FSM_LEN1_S

        elif(FTP_FSM_LEN1_S == self.__state):
            self.__headchecksum += c
            self.__data_len = c
            self.__state = FTP_FSM_LEN2_S

        elif(FTP_FSM_LEN2_S == self.__state):
            self.__headchecksum += c
            if ( self.__headchecksum == self.__recv_head_checksum ):
                self.__data_len += c * 256
                self.__state = FTP_FSM_DATA_S
            else:
                self.__state = FTP_FSM_HEAD_S

        elif(FTP_FSM_DATA_S == self.__state):
            self.__checksum += c
            self.__buf.append(c)
            if (len(self.__buf) == self.__data_len):
                self.__state = FTP_FSM_CHECK_S

        elif(FTP_FSM_CHECK_S == self.__state):
            if ((self.__checksum & 0xFF) == c):
                self.__state = FTP_FSM_END_S
            else:
                self.__state = FTP_FSM_HEAD_S
                
        elif(FTP_FSM_END_S == self.__state):
            if (FRAME_END == c):
                self.__state = FTP_FSM_HEAD_S
                return self.__buf
            else:
                self.__state = FTP_FSM_HEAD_S 

    def clear_buf(self):
        self.__buf = []

    def get_buf(self):
        return self.__buf

ftp_process = file_transfer_protocol_process()

def bytes_to_hex_str(bytes_data):
    hex_data = str(binascii.b2a_hex(bytes_data))
    a = ''
    for num in range(0, len(hex_data) / 2):
        a = a + hex_data[num * 2] + hex_data[num * 2 + 1] + ' '
    return a

def calc_add_checksum(data):
    ret = 0
    for c in data:
        ret = ret + ord(c)
    return ret & 0xFF

def calc_32bit_xor(data):
    bytes_len = len(data)
    data_bytes = bytes(data)
    checksum = bytearray.fromhex("00 00 00 00")
    for i in range(int(bytes_len / 4)):
        checksum[0] = checksum[0] ^ ord(data_bytes[i * 4 + 0])
        checksum[1] = checksum[1] ^ ord(data_bytes[i * 4 + 1])
        checksum[2] = checksum[2] ^ ord(data_bytes[i * 4 + 2])
        checksum[3] = checksum[3] ^ ord(data_bytes[i * 4 + 3])

    if (bytes_len % 4):
        for i in range(bytes_len % 4):
            checksum[0 + i] = checksum[0 + i] ^ ord(data_bytes[4 * int(bytes_len / 4) + i])
    return checksum

def hex2byte(h):
    h = h[2:]
    a = ''
    for num in range(0, len(h) / 2):
        a = a + h[num * 2] + h[num * 2 + 1] + ' '
    return a

def int2hex(input,length,byteorder):
    a = ''
    h = hex(input)[2:]
    if len(h) % 2:
        h = '0' + h
    if byteorder == 'little':
        h = h.decode('hex')[::-1].encode('hex')
    elif byteorder == 'large':
        h = h
    if (len(h) + 1) / 2 >= length:
        return '0x' + h

    if length > (len(h) + 1) / 2:
        for num in range(0, (length - (len(h) + 1) / 2)):
            a += '00'
    if byteorder == 'little':
        h = h + a
    elif byteorder == 'large':
        h = a + h
    return '0x' + h

def int2byte(input,length,byteorder):
    h = int2hex(input, length, byteorder)
    return hex2byte(h)

def send_file(ser, input_file_path, target_file_path):
    global command_result
    global time_count
    global retransmission_count

    input_file_fd = open(input_file_path, 'rb')
    input_file_data = input_file_fd.read()
    input_file_len = len(input_file_data)
    try:
        progress_bar.start(input_file_len)
    except:
	    progress_bar.start()
    # Send file header
    # 1(file_type) + 4(file_size) + 4(file_check_sum) = 0x09
    cmd_len_str = int2byte(0x09 + len(target_file_path), 2, 'little')
    input_file_size_str = int2byte(input_file_len, 4, 'little')
    input_file_checksum_str = bytes_to_hex_str(calc_32bit_xor(input_file_data))
    input_file_name_str = bytes_to_hex_str(bytes(target_file_path))
    frame_data_str = protocol_id_str + " " + dev_id_str + " " + srv_id_str + " " + \
                     file_header_cmd_id_str + " " + cmd_len_str + " " + file_type_str + " " + \
                     input_file_size_str + " " + input_file_checksum_str + " " + input_file_name_str;
    frame_data_str = frame_data_str.replace(' ', '')
    frame_data_len = len(binascii.a2b_hex(frame_data_str))
    frame_data_len_str = int2byte(frame_data_len, 2, 'little' )
    frame_data_len_str = frame_data_len_str.replace(' ', '')
    frame_head_checkusum_str = int2byte(calc_add_checksum(binascii.a2b_hex(frame_header_str + frame_data_len_str)), 1, 'little')
    frame_checksum_str = int2byte(calc_add_checksum(binascii.a2b_hex(frame_data_str)), 1, 'little')

    send_head_str = frame_header_str + " " + frame_head_checkusum_str + " " + frame_data_len_str + " " + \
                    frame_data_str + " " + frame_checksum_str + " " + frame_end_str
    send_head_str = send_head_str.replace(' ', '')
    command_result = False
    ser.write(binascii.a2b_hex(send_head_str))
    current_timeCount = time_count;
    retransmission_count = 0
    while command_result != True:
        if((time_count - current_timeCount) > COMMAND_MAX_TIME_OUT):
            retransmission_count = retransmission_count + 1
            print("resend the file header[" + str(retransmission_count) + "]")
            ser.write(binascii.a2b_hex(send_head_str))
            if retransmission_count >= 5:
                failed_to_exit = True
                update_completed = False
                print("Send header time out!")
                os._exit(1)
                return
            current_timeCount = time_count

    # Send file block
    file_offset = 0
    while (file_offset < input_file_len):
        if ((file_offset + FILE_BLOCK_SIZE) < input_file_len):
            send_file_size = FILE_BLOCK_SIZE
        else:
            send_file_size = input_file_len - file_offset

        file_offset_str = int2byte(file_offset, 4, 'little')
        cmd_len_str = int2byte((0x04 + send_file_size), 2, 'little')
        file_block_str = bytes_to_hex_str(bytes(input_file_data[file_offset:file_offset + send_file_size]))
        frame_data_str = protocol_id_str + " " + dev_id_str + " " + srv_id_str + " " + file_block_cmd_id_str + \
                         " " + cmd_len_str + " " + file_offset_str + " " + file_block_str;
        frame_data_str = frame_data_str.replace(' ', '')
        frame_data_len = len(binascii.a2b_hex(frame_data_str))
        frame_data_len_str = int2byte(frame_data_len, 2, 'little')
        frame_data_len_str = frame_data_len_str.replace(' ', '')
        frame_head_checkusum_str = int2byte(calc_add_checksum(binascii.a2b_hex(frame_header_str + frame_data_len_str)), 1, 'little')
        frame_checksum_str = int2byte(calc_add_checksum(binascii.a2b_hex(frame_data_str)), 1, 'little' )

        send_block_str = frame_header_str + " " + frame_head_checkusum_str + " " + frame_data_len_str + \
                         " " + frame_data_str + " " + frame_checksum_str + " " + frame_end_str
        send_block_str = send_block_str.replace(' ', '')
        send_block_bytes = binascii.a2b_hex(send_block_str);
        command_result = False
        ser.write(send_block_bytes)
        current_timeCount = time_count;
        retransmission_count = 0
        while command_result != True:
            if((time_count - current_timeCount) > COMMAND_MAX_TIME_OUT):
                retransmission_count = retransmission_count + 1
                print("resend the file block[" + str(retransmission_count) + "]")
                ser.write(send_block_bytes)
                if retransmission_count >= 3:
                    failed_to_exit = True
                    update_completed = False
                    print("Send file block time out!")
                    os._exit(1)
                    return
                current_timeCount = time_count
        file_offset = file_offset + send_file_size
        progress_bar.update(file_offset)
    progress_bar.finish()
    update_completed = True
    print("Complete file:[" + input_file_path + "] transfer!")
    os._exit(1)

def firmware_update_task():
    global serial_fd
    global input_file_path
    global target_file_path
    send_file(serial_fd, input_file_path, target_file_path)

def receive_task():
    global serial_fd
    global command_result
    while True:
        try:
           if(serial_fd.readable()):
                receive_buffer = serial_fd.read(serial_fd.inWaiting())
                for c in receive_buffer:
                    buf_list = ftp_process.push_char(c)
                    if (type(buf_list) == list):
                        if (0x01 == buf_list[0] and 0x00 == buf_list[6]):
                            command_result = True
                        else:
                            command_result = False
                        ftp_process.clear_buf()
        except:
            sys.exit(1)

def time_count_task():
    global time_count
    while( True ):
        time_count = time_count + 1
        time.sleep(0.1)

def main_task(serial_name_temp, input_file_path_temp, target_file_path_temp):
    global serial_name
    global serial_fd
    global input_file_path
    global target_file_path
    global failed_to_exit
    global update_completed
    failed_to_exit = False
    update_completed = False

    serial_name = serial_name_temp 
    input_file_path = input_file_path_temp
    target_file_path = target_file_path_temp

    port_list = list(serial.tools.list_ports.comports())

    if len(port_list) <= 0:
        print("None Serial port been find!")
        failed_to_exit = True
    else:
        time_count_thread = threading.Thread(target = time_count_task)
        time_count_thread.setDaemon(True)  
        time_count_thread.start()
        serial_searched = False
        for i in range(len(port_list)):
            port_list_0 = list(port_list[i])
            port_serial = port_list_0[0]
            if serial_name == None:
                serial_name = port_serial
            if re.match(serial_name, port_serial) != None:
                serial_fd = serial.Serial(serial_name, 115200, timeout = 0.1)
                firmware_update_thread = threading.Thread(target = firmware_update_task)
                firmware_update_thread.setDaemon(True)  
                firmware_update_thread.start()
                receive_thread = threading.Thread(target = receive_task)
                receive_thread.setDaemon(True)  
                receive_thread.start()
                time_count_thread = threading.Thread(target = time_count_task)
                time_count_thread.setDaemon(True)  
                time_count_thread.start()
                serial_searched = True
                break
        if serial_searched == False:
            print("The serial port[" + serial_name + "] entered is incorrect!")
            failed_to_exit = True

    while True:
        if failed_to_exit == True:
            sys.exit(1)
            break
        if update_completed == True:
            sys.exit(2)
            break