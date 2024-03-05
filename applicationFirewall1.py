class HTTPRequest:
    def __init__(self, source_ip, method, url):
        self.source_ip = source_ip
        self.method = method
        self.url = url

class Firewall:
    def __init__(self):
        self.blocked_urls = []

    def block_url(self, url):
        self.blocked_urls.append(url)

    def allow_request(self, request):
        if request.url in self.blocked_urls:
            return False
        return True

# Initialize the firewall
firewall = Firewall()

# Add URLs to block
firewall.block_url("/admin")
firewall.block_url("/private")

# Define a function to process incoming requests
def process_request(request):
    if firewall.allow_request(request):
        print("Allowed request:", request.method, request.url)
    else:
        print("Blocked request:", request.method, request.url)

# Simulate incoming HTTP requests
requests = [
    HTTPRequest("192.168.1.1", "GET", "/"),
    HTTPRequest("192.168.1.2", "GET", "/admin"),
    HTTPRequest("192.168.1.3", "POST", "/login")
]

# Start processing requests in a loop
for request in requests:
    process_request(request)
