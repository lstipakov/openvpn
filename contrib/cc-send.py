import socket
import sys

def main():
    msg = sys.argv[1] if len(sys.argv) > 1 else "hello" 
    msg = msg.replace(" ", r"\ ")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 7505))
    cmd = "cc-send %s\n" % msg
    s.send(cmd.encode("utf-8"))
    s.close()

if __name__ == "__main__":
    main()
