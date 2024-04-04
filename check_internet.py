import urllib.request

def check_internet():
    try:
        urllib.request.urlopen('http://google.com', timeout=10)
        print("Internet connection appears to be working")
    except urllib.error.URLError as err:
        print("No Internet Connection: ", err)

if __name__ == "__main__":
    check_internet()
