import requests
from os.path import dirname, realpath

requests.packages.urllib3.disable_warnings()

test_dir = dirname(realpath(__file__))

# http 301
r = requests.get('http://10.0.0.1/index.html', allow_redirects=False)
assert(r.status_code == 301 and r.headers['Location'] == 'https://10.0.0.1/index.html')
print("test1 passed")

# https 200 OK
r = requests.get('https://10.0.0.1/index.html', verify=False)
assert(r.status_code == 200 and open(test_dir + '/../index.html', 'rb').read() == r.content)
print("test2 passed")

# http 200 OK
r = requests.get('http://10.0.0.1/index.html', verify=False)
assert(r.status_code == 200 and open(test_dir + '/../index.html', 'rb').read() == r.content)
print("test3 passed")

# http 404
r = requests.get('http://10.0.0.1/notfound.html', verify=False)
assert(r.status_code == 404)
print("test4 passed")

# file in directory
r = requests.get('http://10.0.0.1/dir/index.html', verify=False)
assert(r.status_code == 200 and open(test_dir + '/../index.html', 'rb').read() == r.content)
print("test5 passed")

# http 206
headers = { 'Range': 'bytes=100-200' }
r = requests.get('http://10.0.0.1/index.html', headers=headers, verify=False)
print(r.content)
print()
print(open(test_dir + '/../index.html', 'rb').read()[100:201])
assert(r.status_code == 206 and open(test_dir + '/../index.html', 'rb').read()[100:201] == r.content)
print("test6 passed")

# http 206
headers = { 'Range': 'bytes=100-' }
r = requests.get('http://10.0.0.1/index.html', headers=headers, verify=False)
assert(r.status_code == 206 and open(test_dir + '/../index.html', 'rb').read()[100:] == r.content)
print("test7 passed")
