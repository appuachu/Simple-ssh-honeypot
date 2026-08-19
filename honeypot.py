#!/usr/bin/env python3
import socket
import threading
import datetime
import paramiko
import os
import sys
import time

HOST = '0.0.0.0'
PORT = 2222
LOG_FILE = 'honeypot.log'

FAKE_USERS = {
    'root': 'password123',
    'admin': 'admin123',
    'user': 'user123',
    'test': 'test123',
    'ubuntu': 'ubuntu',
    'debian': 'debian',
    'oracle': 'oracle',
    'postgres': 'postgres'
}

def log_attempt(ip, username, password, status):
    timestamp = datetime.datetime.now().isoformat()
    if status == 'SUCCESS':
        print(f"\033[92m[{timestamp}] \033[93m{ip}\033[0m - {username}:{password} - \033[92m✅ {status}\033[0m")
    else:
        print(f"[{timestamp}] {ip} - {username}:{password} - ❌ {status}")
    with open(LOG_FILE, 'a') as f:
        f.write(f"{timestamp} | {ip} | {username} | {password} | {status}\n")

def log_command(ip, username, command):
    timestamp = datetime.datetime.now().isoformat()
    print(f"[{timestamp}] \033[93m{ip}\033[0m - {username} ran: \033[94m{command}\033[0m")
    with open(LOG_FILE, 'a') as f:
        f.write(f"{timestamp} | {ip} | {username} | COMMAND: {command}\n")

def get_fake_response(command):
    """Return fake output for commands"""
    cmd = command.strip()
    
    # Exact command matches
    if cmd == 'ls':
        return 'Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos\n'
    
    if cmd == 'ls -la':
        return '''total 48
drwxr-xr-x  5 root root 4096 Aug 19 10:00 .
drwxr-xr-x 22 root root 4096 Aug 19 09:30 ..
-rw-r--r--  1 root root  220 Aug 19 08:00 .bash_logout
-rw-r--r--  1 root root 3771 Aug 19 08:00 .bashrc
-rw-r--r--  1 root root  807 Aug 19 08:00 .profile
drwxr-xr-x  2 root root 4096 Aug 19 08:00 Desktop
drwxr-xr-x  2 root root 4096 Aug 19 08:00 Documents
drwxr-xr-x  2 root root 4096 Aug 19 08:00 Downloads\n'''
    
    if cmd == 'whoami':
        return 'root\n'
    
    if cmd == 'id':
        return 'uid=0(root) gid=0(root) groups=0(root)\n'
    
    if cmd == 'pwd':
        return '/root\n'
    
    if cmd == 'uptime':
        return ' 10:00:00 up 2 days,  3:15,  1 user,  load average: 0.00, 0.01, 0.05\n'
    
    if cmd == 'date':
        return datetime.datetime.now().strftime('%a %b %d %H:%M:%S UTC %Y\n')
    
    if cmd == 'cat /etc/passwd':
        return '''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:104::/nonexistent:/usr/sbin/nologin
syslog:x:103:106::/home/syslog:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
user:x:1000:1000:user:/home/user:/bin/bash\n'''
    
    if cmd == 'ps aux':
        return '''USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  16836  1200 ?        Ss   Aug18   0:02 /sbin/init
root         2  0.0  0.0      0     0 ?        S    Aug18   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   Aug18   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   Aug18   0:00 [rcu_par_gp]
root         6  0.0  0.0      0     0 ?        I<   Aug18   0:00 [kworker/0:0H]
root         9  0.0  0.0      0     0 ?        I<   Aug18   0:00 [mm_percpu_wq]
root        10  0.0  0.0      0     0 ?        S    Aug18   0:00 [ksoftirqd/0]
root        11  0.0  0.0      0     0 ?        R    Aug18   0:00 [rcu_sched]
root        12  0.0  0.0      0     0 ?        S    Aug18   0:00 [migration/0]
root        13  0.0  0.0      0     0 ?        S    Aug18   0:00 [idle_inject/0]
root        14  0.0  0.0      0     0 ?        S    Aug18   0:00 [cpuhp/0]
root        15  0.0  0.0      0     0 ?        S    Aug18   0:00 [cpuhp/1]
root        16  0.0  0.0      0     0 ?        S    Aug18   0:00 [idle_inject/1]
root        17  0.0  0.0      0     0 ?        S    Aug18   0:00 [migration/1]
root        18  0.0  0.0      0     0 ?        S    Aug18   0:00 [ksoftirqd/1]\n'''
    
    if cmd == 'netstat -an':
        return '''Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN\n'''
    
    if cmd == 'df -h':
        return '''Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1       100G   30G   70G  30% /
tmpfs           2.0G     0  2.0G   0% /dev/shm\n'''
    
    if cmd == 'uname -a':
        return 'Linux honeypot 5.15.0-76-generic #83-Ubuntu SMP Thu Jun 15 19:01:37 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n'
    
    if cmd == 'clear':
        return ''
    
    if cmd == 'history':
        return '    1  ls\n    2  whoami\n    3  pwd\n    4  cat /etc/passwd\n'
    
    if cmd == 'exit' or cmd == 'logout' or cmd == 'quit':
        return 'logout\n'
    
    if cmd == 'help':
        return '''Built-in commands:
ls              - List files
whoami          - Show current user
id              - Show user/group info
pwd             - Show current directory
uptime          - Show system uptime
date            - Show current date/time
cat /etc/passwd - Show password file
ps aux          - Show processes
netstat -an     - Show network connections
df -h           - Show disk usage
uname -a        - Show system info
clear           - Clear screen
history         - Show command history
exit            - Exit session\n'''
    
    # Handle echo commands
    if cmd.startswith('echo '):
        return cmd[5:] + '\n'
    
    # Handle cd commands
    if cmd.startswith('cd '):
        return ''
    
    # Unknown command
    return f'bash: {cmd}: command not found\n'

class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.username = None
        self.event = threading.Event()
    
    def check_auth_password(self, username, password):
        self.username = username
        if username in FAKE_USERS and FAKE_USERS[username] == password:
            log_attempt(self.client_ip, username, password, 'SUCCESS')
            return paramiko.AUTH_SUCCESSFUL
        else:
            log_attempt(self.client_ip, username, password, 'FAILED')
            return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        return 'password'
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    def check_channel_exec_request(self, channel, command):
        cmd = command.decode('utf-8') if isinstance(command, bytes) else command
        log_command(self.client_ip, self.username, cmd)
        response = get_fake_response(cmd)
        channel.send(response.encode())
        channel.send_exit_status(0)
        return True

def shell_thread(channel, client_ip, username):
    try:
        # Send welcome message
        channel.send('\r\n')
        channel.send('Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-76-generic x86_64)\r\n')
        channel.send('\r\n')
        channel.send(' * Documentation:  https://help.ubuntu.com\r\n')
        channel.send(' * Management:     https://landscape.canonical.com\r\n')
        channel.send(' * Support:        https://ubuntu.com/advantage\r\n')
        channel.send('\r\n')
        channel.send(f'  System information as of {datetime.datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")}\r\n')
        channel.send('\r\n')
        channel.send(f'  System load:  0.08              Processes:             124\r\n')
        channel.send(f'  Usage of /:   30.2% of 98.42GB   Users logged in:       1\r\n')
        channel.send(f'  Memory usage: 12%               IPv4 address for eth0:  {client_ip}\r\n')
        channel.send(f'  Swap usage:   0%\r\n')
        channel.send('\r\n')
        channel.send(f'Last login: {datetime.datetime.now().strftime("%a %b %d %H:%M:%S")} from {client_ip}\r\n')
        channel.send('\r\n')
        
        # Main shell loop
        while True:
            # Send prompt with color
            prompt = f'\x1b[01;32m{username}@kali\x1b[00m:\x1b[01;34m~$\x1b[00m '
            channel.send(prompt)
            
            # Read command
            command = ''
            while True:
                try:
                    char = channel.recv(1)
                    if not char:
                        return
                    char = char.decode('utf-8', errors='ignore')
                    
                    if char == '\r' or char == '\n':
                        break
                    elif char == '\x7f' or char == '\x08':  # Backspace
                        if command:
                            command = command[:-1]
                            # Remove from display
                            channel.send('\x08 \x08')
                    elif char == '\x03':  # Ctrl+C
                        command = ''
                        channel.send('^C\r\n')
                        break
                    else:
                        command += char
                        channel.send(char)
                except:
                    return
            
            # Clean command
            command = command.strip()
            
            # Handle empty command
            if not command:
                continue
            
            # Log the command
            log_command(client_ip, username, command)
            
            # Check for exit
            if command.lower() in ['exit', 'logout', 'quit']:
                channel.send('logout\r\n')
                break
            
            # Get response
            response = get_fake_response(command)
            
            # Send response with proper newlines
            if response:
                channel.send('\r\n')
                channel.send(response)
                if not response.endswith('\n'):
                    channel.send('\r\n')
            
            channel.send('\r\n')
            
    except Exception as e:
        print(f"Shell error: {e}")
    finally:
        try:
            channel.close()
        except:
            pass

def handle_client(client_socket, client_addr):
    client_ip = client_addr[0]
    try:
        transport = paramiko.Transport(client_socket)
        transport.set_gss_host(socket.getfqdn())
        
        # Load host key
        try:
            host_key = paramiko.RSAKey.from_private_key_file('host_rsa_key')
            transport.add_server_key(host_key)
        except:
            host_key = paramiko.RSAKey.generate(2048)
            transport.add_server_key(host_key)
        
        # Start server
        server = HoneypotSSHServer(client_ip)
        transport.start_server(server=server)
        
        # Wait for auth
        channel = transport.accept(30)
        if channel is None:
            return
        
        # Get username
        username = server.username or 'root'
        
        # Start shell
        shell_thread(channel, client_ip, username)
        
    except Exception as e:
        print(f"Error with {client_ip}: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass

def main():
    try:
        import paramiko
    except ImportError:
        print("❌ paramiko not installed. Run: pip3 install paramiko")
        sys.exit(1)
    
    # Generate host keys
    if not os.path.exists('host_rsa_key'):
        print("🔑 Generating host keys...")
        os.system("ssh-keygen -t rsa -f host_rsa_key -N '' 2>/dev/null")
        print("✅ Host keys generated")
    
    # Start server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(100)
    except Exception as e:
        print(f"❌ Failed to bind to port {PORT}: {e}")
        sys.exit(1)
    
    print("=" * 70)
    print("🔐  SSH HONEYPOT")
    print("=" * 70)
    print(f"📡 Listening on: {HOST}:{PORT}")
    print(f"📝 Logging to:   {LOG_FILE}")
    print("=" * 70)
    print("📋 Fake credentials:")
    for user, passwd in FAKE_USERS.items():
        print(f"   👤 {user}  🔑 {passwd}")
    print("=" * 70)
    print("✅ Honeypot is RUNNING")
    print("   Press Ctrl+C to stop")
    print("=" * 70)
    
    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            client_ip = client_addr[0]
            print(f"[{datetime.datetime.now().isoformat()}] 🌐 New connection from: {client_ip}")
            thread = threading.Thread(target=handle_client, args=(client_socket, client_addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n🛑 Stopping honeypot...")
        server_socket.close()
        sys.exit(0)

if __name__ == '__main__':
    main()
