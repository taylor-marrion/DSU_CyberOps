#!/usr/bin/env python3
import socket
Q
HOST = "127.0.0.1"
PORT = 8080

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    print(f"[+] Listening on {HOST}:{PORT}")

    current_task = "SLEEP=3"  # default

    while True:
        conn, addr = srv.accept()
        print(f"[+] Connection from {addr}")

        data = conn.recv(4096)
        try:
            print("[<] Request:\n" + data.decode(errors="replace"))
        except Exception:
            print("[<] (binary request)")

        # Update task interactively
        user = input(f"Task to send (enter keeps '{current_task}'): ").strip()
        if user:
            current_task = user

        body = current_task.encode()
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
        conn.sendall(resp)
        conn.close()
        print(f"[>] Sent task: {current_task}\n")

if __name__ == "__main__":
    main()
