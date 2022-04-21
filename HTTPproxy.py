# Place your imports here
import signal
import sys
from optparse import OptionParser
from socket import *
from urllib.parse import urlparse
import re
from _thread import *
import os
import shutil

blockList = []
blocklistController = False
cacheController = False


# TODO: Put function definitions here
# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)


def check_blocklist(url):
    global blockList
    global blocklistController

    if '/proxy/blocklist/enable' in url:
        print("Blocklist enabled")
        blocklistController = True
        return

    elif '/proxy/blocklist/disable' in url:
        print("Blocklist disabled")
        blocklistController = False
        return

    elif '/proxy/blocklist/add/' in url:
        url = url.split('/')
        host = url[len(url) - 1]

        if host not in blockList:
            blockList.append(host)

        return

    elif '/proxy/blocklist/remove/' in url:
        url = url.split('/')
        host = url[len(url) - 1]

        if host in blockList:
            blockList.remove(host)

        return

    # flush otherwise
    else:
        blockList.clear()
        return


def conditionalGet(filename):
    date = ""

    file = open("./cache/" + filename, "rb")
    text = file.read()

    findNewline = re.search(b'\r\n\r\n', text)
    text = text[:findNewline.start()].decode()

    checkDate = ""
    if text.find("Last-Modified") != -1:
        checkDate = text.find("Last-Modified")

    else:
        checkDate = text.find("Date")

    part = text[checkDate:].partition('\n')

    mod = part[0]

    mod = mod.partition(':')

    date = mod[len(mod) - 1]
    file.close()

    return date


def fetch_file(filename, method, path, HttpVersion, hostname, Headers, url, tcp, c):
    # Let's try to read the file locally first
    file_from_cache = fetch_from_cache(tcp, url, hostname, c)

    if file_from_cache is not None:
        print('Fetched successfully from cache.')
        return
    else:
        print('Not in cache. Fetching from server.')
        fetch_from_server(method, path, HttpVersion, hostname, Headers, tcp, url, c)
        return


def fetch_from_cache(tcp, url, hostname, c):
    try:
        message = ''
        if cacheController:
            filename = str(hash(url))
            fin = os.path.isfile('./cache/' + filename)
            if fin:
                date = conditionalGet(filename)

                # send conditional get to server
                message += 'If-Modified-Since:' + date + '\r\n'
                message += 'Connection: close\r\n\r\n'
                c.sendall(message.encode())

                data = b''

                # receive until the CRLF is found
                while True:
                    more = c.recv(1024)
                    data += more

                    if data.endswith(b'\r\n\r\n'):
                        break

                        # split on the headers
                findNewline = re.search(b'\r\n\r\n', data)
                responseHeaders = data[:findNewline.start()].decode()

                # check if 304 Not modified
                if responseHeaders.find('HTTP/1.1 304 Not Modified') == 1:
                    file = open('./cache/' + filename, "wb+")
                    file.write(data)
                    file.close()

                # send the data in the cache
                data = b''
                file = open('./cache/' + filename, "rb")
                data = file.read()

                # send to client
                tcp.send(data)
                tcp.close()

                file.close()
                return 1

    except IOError:
        return None


def fetch_from_server(method, path, HttpVersion, hostname, Headers, tcp, url, c):
    sendQuest = method + ' ' + path + ' ' + HttpVersion + '\r\n' + 'Host:' + ' ' + hostname + '\r\n'
    for header in Headers:
        if header != "Connection: close":
            sendQuest = sendQuest + header + "\r\n"

    sendQuest = sendQuest + 'Connection: close' + '\r\n\r\n'
    c.sendall(sendQuest.encode())
    content = b''
    while True:
        response = c.recv(1024)
        if len(response) == 0:
            tcp.sendall(content)
            if cacheController:
                filename = str(hash(url))
                findNewline = re.search(b'\r\n\r\n', content)
                responseHeaders = content[:findNewline.start()].decode()

                if responseHeaders.find('200 OK') != 1:
                    file = open("./cache/" + filename, "wb+")
                    file.write(content)
                    file.close()

            tcp.close()
            return
        else:
            content += response
            continue


# def save_in_cache(filename, content):
#     print('Saving a copy of {} in the cache'.format(filename))
#     # filename=remov(filename)
#     cached_file = open("./cache" + filename, "wb+")
#     cached_file.write(content)
#     cached_file.close()

def connection(tcp):
    global blocklistController
    global blockList
    global cacheController

    port = 80
    method = HttpVersion = hostname = path = None
    message = ''
    data = ''
    Headers = []
    url = ''

    while True:
        more = tcp.recv(1024)
        data += more.decode()

        if data.endswith('\r\n\r\n'):
            break

    lines = data.splitlines()

    if not lines[len(lines) - 1] == '':
        message = 'HTTP/1.0 400 Bad Request\r\n\r\n'
        tcp.sendall(message.encode())
        tcp.close()
        return

    for line in lines:
        if line == lines[0]:
            try:
                method = line.split(' ')[0]
                url = line.split(' ')[1]
                HttpVersion = line.split(' ')[2]
            except IndexError:
                message = 'HTTP/1.0 400 Bad Request\r\n\r\n'
                tcp.sendall(message.encode())
                tcp.close()
                return
            lineSplit = line.split(' ')
            if len(lineSplit) != 3:
                message = "HTTP/1.0 400 Bad Request\r\n\r\n"
                tcp.send(message.encode())
                tcp.close()
                return
            parsed = urlparse(url)
            if not bool(parsed.netloc):
                message = "HTTP/1.0 400 Bad Request\r\n\r\n"
                tcp.send(message.encode())
                tcp.close()
                return
            if parsed.path is None or parsed.path == '':
                message = "HTTP/1.0 400 Bad Request\r\n\r\n"
                tcp.send(message.encode())
                tcp.close()
                return
            if parsed.port is not None:
                port = parsed.port
            if parsed.hostname is not None:
                hostname = parsed.hostname
            if parsed.path is not None:
                path = parsed.path
            if method != 'GET':
                if method == 'HEAD' or method == 'POST':
                    message = "HTTP/1.0 501 Not Implemented\r\n\r\n"
                    tcp.sendall(message.encode())
                    tcp.close()
                    return
                else:
                    message = "HTTP/1.0 400 Bad Request\r\n\r\n"
                    tcp.sendall(message.encode())
                    tcp.close()
                    return
        else:
            if line != lines[(len(lines) - 1)]:
                string_pattern = "([\w-]+): (.*)"
                regex_pattern = re.compile(string_pattern)
                patterns_found = regex_pattern.findall(line)
                if len(patterns_found) == 0:
                    message = "HTTP/1.0 400 Bad Request\r\n\r\n"
                    tcp.send((message.encode()))
                    tcp.close()
                    return
                if not line == 'Connection: keep-alive':
                    Headers.append(line)

    if not HttpVersion == 'HTTP/1.0':
        message = 'HTTP/1.0 400 Bad Request\r\n\r\n'
        tcp.sendall(message.encode())
        tcp.close()
        return

    if '/proxy/cache/' in url:
        if '/proxy/cache/enable' in url:
            cacheController = True

        elif 'proxy/cache/disable' in url:
            cacheController = False

        # Flush otherwise
        else:
            shutil.rmtree('./cache')
            os.mkdir('./cache')

        message = 'HTTP/1.0 200 OK\r\n\r\n'
        tcp.sendall(message.encode())
        tcp.close()
        return

    if '/proxy/blocklist/' in url:
        check_blocklist(url)
        message = 'HTTP/1.0 200 OK\r\n\r\n'
        tcp.sendall(message.encode())
        tcp.close()
        return

    if blocklistController:
        checkHostName = hostname
        checkHostName += ':' + str(port)

        for name in blockList:
            if name in checkHostName:
                message = 'HTTP/1.0 403 Forbidden\r\n\r\n'
                tcp.sendall(message.encode())
                tcp.close()
                return

    c = socket(AF_INET, SOCK_STREAM)
    c.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    c.connect((hostname, port))

    fetch_file(filename, method, path, HttpVersion, hostname, Headers, url, tcp, c)

    return


# Start of program execution
# Parse out the command line server address and port number to listen to
parser = OptionParser()
parser.add_option('-p', type='int', dest='serverPort')
parser.add_option('-a', type='string', dest='serverAddress')
(options, args) = parser.parse_args()
port = options.serverPort
address = options.serverAddress
if address is None:
    address = 'localhost'
if port is None:
    port = 2100
# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)
# TODO: Set up sockets to receive requests
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.bind((address, port))
serverSocket.listen(1)
filename = ''
if os.path.isdir('./cache/'):
    os.rmdir('./cache')

os.mkdir('./cache')

while True:
    tcp, address = serverSocket.accept()
    start_new_thread(connection, (tcp,))

serverSocket.close()

