import logging
import json
import urllib.request
import urllib.error
import ssl
from urllib.parse import urljoin

class APIEnumerator:
    def __init__(self, target, port=443, protocol='https', timeout=10, username='', password=''):
        self.target = target
        self.port = port
        self.protocol = protocol
        self.timeout = timeout
        self.username = username
        self.password = password
        self.base_url = f"{protocol}://{target}:{port}"
        self.endpoints_found = []
        self.api_version = None

        # Configure logging
        self.logger = logging.getLogger('APIEnumerator')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

        # Disable SSL warnings for self-signed certs
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        self.ssl_context = ssl_context

    def connect(self):
        """Test connectivity to the API endpoint."""
        self.logger.info(f"Testing connectivity to {self.base_url}...")
        try:
            req = urllib.request.Request(self.base_url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            if self.protocol == 'https':
                opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ssl_context))
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
                
            response = opener.open(req, timeout=self.timeout)

            self.logger.info(f"Successfully connected to {self.base_url}")
            return True
        except urllib.error.HTTPError as e:
            self.logger.info(f"Connected (HTTP {e.code})")
            return True
        except Exception as e:
            self.logger.error(f"Connection Error: {e}")
            return False

    def discover_api_paths(self):
        """Discover common API paths and endpoints."""
        self.logger.info("Discovering API paths...")

        common_api_paths = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/apis',
            '/rest',
            '/rest/api',
            '/rest/api/v1',
            '/graphql',
            '/graphql/query',
            '/swagger',
            '/swagger-ui',
            '/swagger-ui.html',
            '/api-docs',
            '/api/docs',
            '/openapi',
            '/openapi.json',
            '/openapi.yaml',
            '/openapi.yml',
            '/spec',
            '/api/spec',
            '/docs',
            '/documentation',
            '/api/documentation',
            '/api.json',
            '/api.yaml',
            '/swagger.json',
            '/swagger.yaml',
            '/.well-known/openapi.json',
            '/actuator',
            '/actuator/health',
            '/health',
            '/status',
            '/admin',
            '/admin/api',
            '/service',
            '/services',
            '/public/api',
        ]

        discovered = []
        for path in common_api_paths:
            url = urljoin(self.base_url, path)
            status_code, content_type = self._check_endpoint(url)

            if status_code and status_code < 500:
                discovered.append({
                    'path': path,
                    'status': status_code,
                    'content_type': content_type
                })
                self.logger.info(f"[+] Found: {path} (Status: {status_code})")
                self.endpoints_found.append({'path': path, 'status': status_code, 'content_type': content_type})

        return discovered

    def discover_endpoints(self):
        """Discover specific API endpoints."""
        self.logger.info("Discovering API endpoints...")

        common_endpoints = [
            '/users',
            '/user',
            '/accounts',
            '/account',
            '/profile',
            '/me',
            '/auth',
            '/login',
            '/logout',
            '/register',
            '/signup',
            '/posts',
            '/products',
            '/items',
            '/data',
            '/config',
            '/settings',
            '/admin/users',
            '/admin/settings',
            '/database',
            '/files',
            '/upload',
            '/download',
            '/search',
            '/query',
            '/webhook',
            '/webhooks',
            '/version',
            '/versions',
            '/info',
            '/about',
        ]

        discovered = []
        for endpoint in common_endpoints:
            # Try both with /api/v1 prefix and without
            paths_to_try = [
                f'/api/v1{endpoint}',
                f'/api{endpoint}',
                endpoint,
            ]

            for path in paths_to_try:
                url = urljoin(self.base_url, path)
                status_code, content_type = self._check_endpoint(url)

                if status_code and status_code < 500:
                    discovered.append({
                        'path': path,
                        'status': status_code,
                        'content_type': content_type
                    })
                    self.logger.info(f"[+] Found: {path} (Status: {status_code})")
                    if {'path': path, 'status': status_code, 'content_type': content_type} not in self.endpoints_found:
                        self.endpoints_found.append({'path': path, 'status': status_code, 'content_type': content_type})

        return discovered

    def _check_endpoint(self, url):
        """Check if an endpoint exists and return status code and content type."""
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')

            if self.username and self.password:
                import base64
                credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
                req.add_header('Authorization', f'Basic {credentials}')

            if url.startswith('https'):
                opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ssl_context))
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            
            response = opener.open(req, timeout=self.timeout)

            status_code = response.status
            content_type = response.headers.get('Content-Type', 'N/A')
            return status_code, content_type
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get('Content-Type', 'N/A')
        except:
            return None, None

    def check_api_vulnerabilities(self):
        """Check for common API vulnerabilities."""
        self.logger.info("Checking for common API vulnerabilities...")
        vulnerabilities = {}

        # Check for missing authentication on endpoints
        self.logger.info("Checking for missing authentication...")
        auth_endpoints = ['/api/v1/users', '/api/v1/admin', '/admin/users', '/users']
        for endpoint in auth_endpoints:
            url = urljoin(self.base_url, endpoint)
            status_code, _ = self._check_endpoint(url)

            if status_code == 200:
                vulnerabilities['Missing Authentication'] = f'Endpoint {endpoint} is accessible without auth (VULNERABLE!)'
                self.logger.warning(f"Missing Authentication: {endpoint} is publicly accessible!")
                break

        # Check for CORS misconfiguration
        self.logger.info("Checking for CORS misconfiguration...")
        cors_vulns = self._check_cors()
        if cors_vulns:
            vulnerabilities.update(cors_vulns)

        # Check for exposed API documentation
        self.logger.info("Checking for exposed API documentation...")
        doc_endpoints = ['/swagger-ui.html', '/api-docs', '/openapi.json']
        for doc_endpoint in doc_endpoints:
            url = urljoin(self.base_url, doc_endpoint)
            status_code, _ = self._check_endpoint(url)

            if status_code == 200:
                vulnerabilities['Exposed API Documentation'] = f'{doc_endpoint} is publicly accessible (Information Disclosure)'
                self.logger.warning(f"Exposed API Documentation: {doc_endpoint}")
                break

        # Check for debug endpoints
        self.logger.info("Checking for debug endpoints...")
        debug_endpoints = ['/debug', '/api/debug', '/actuator', '/health']
        for debug_endpoint in debug_endpoints:
            url = urljoin(self.base_url, debug_endpoint)
            status_code, _ = self._check_endpoint(url)

            if status_code == 200:
                vulnerabilities['Debug Endpoint Exposed'] = f'{debug_endpoint} is accessible (Information Disclosure)'
                self.logger.warning(f"Debug Endpoint: {debug_endpoint}")

        if not vulnerabilities:
            vulnerabilities['No Major Issues Found'] = 'Initial scan complete'
            self.logger.info("No major vulnerabilities detected in initial scan.")

        return vulnerabilities

    def _check_cors(self):
        """Check for CORS misconfiguration."""
        cors_issues = {}
        try:
            url = urljoin(self.base_url, '/api/v1/users')
            req = urllib.request.Request(url, method='OPTIONS')
            req.add_header('Origin', 'https://attacker.com')
            req.add_header('Access-Control-Request-Method', 'POST')

            if url.startswith('https'):
                opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ssl_context))
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            
            response = opener.open(req, timeout=self.timeout)

            allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
            allow_credentials = response.headers.get('Access-Control-Allow-Credentials', '')

            if allow_origin == '*':
                cors_issues['CORS Misconfiguration'] = 'Allow-Origin: * found (VULNERABLE!)'
                self.logger.warning("CORS Misconfiguration: Allow-Origin: * detected!")
            elif allow_credentials.lower() == 'true' and allow_origin:
                cors_issues['CORS Misconfiguration'] = f'Allow-Credentials: true with Allow-Origin: {allow_origin} (VULNERABLE!)'
                self.logger.warning("CORS Misconfiguration: Credentials allowed with specific origin!")
        except:
            pass

        return cors_issues

    def test_default_credentials(self):
        """Test for default credentials on API endpoints."""
        self.logger.info("Testing for default credentials...")
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('user', 'user'),
            ('test', 'test'),
            ('root', 'root'),
        ]

        found_creds = {}
        for username, password in default_creds:
            if self._test_credentials(username, password):
                found_creds[f'{username}:{password}'] = 'VALID (VULNERABLE!)'
                self.logger.warning(f"Found valid credentials: {username}:{password}")

        if not found_creds:
            found_creds['No Default Credentials Found'] = 'Good'
            self.logger.info("No default credentials found.")

        return found_creds

    def _test_credentials(self, username, password):
        """Test if provided credentials are valid."""
        try:
            import base64
            url = urljoin(self.base_url, '/api/v1/users')
            req = urllib.request.Request(url)

            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            req.add_header('Authorization', f'Basic {credentials}')
            req.add_header('User-Agent', 'Mozilla/5.0')

            if url.startswith('https'):
                opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ssl_context))
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPHandler())
            response = opener.open(req, timeout=self.timeout)

            return response.status == 200
        except:
            return False

    def get_api_version(self):
        """Try to identify API version."""
        self.logger.info("Attempting to identify API version...")

        version_endpoints = [
            ('/api/v1/version', 'v1'),
            ('/api/v2/version', 'v2'),
            ('/api/version', 'unknown'),
            ('/version', 'unknown'),
            ('/api/v1', 'v1'),
        ]

        for endpoint, expected_version in version_endpoints:
            url = urljoin(self.base_url, endpoint)
            status_code, _ = self._check_endpoint(url)

            if status_code == 200:
                self.api_version = expected_version
                self.logger.info(f"API Version detected: {expected_version}")
                return expected_version

        self.logger.info("Could not identify API version")
        return None

    def enumerate_all(self):
        """Run all enumeration methods and compile results."""
        self.logger.info("Starting comprehensive API enumeration...")

        results = {
            'API Paths': self.discover_api_paths(),
            'API Endpoints': self.discover_endpoints(),
            'Vulnerabilities': self.check_api_vulnerabilities(),
            'Default Credentials': self.test_default_credentials(),
            'API Version': self.get_api_version(),
        }

        return results

    def close(self):
        """Clean up resources."""
        self.logger.info("API enumeration completed.")

if __name__ == '__main__':
    # Test execution example
    enum = APIEnumerator('api.example.com', port=443, protocol='https')
    if enum.connect():
        paths = enum.discover_api_paths()
        print("Discovered API Paths:")
        for path in paths:
            print(f"  {path['path']} - Status: {path['status']}")

        endpoints = enum.discover_endpoints()
        print("\nDiscovered Endpoints:")
        for endpoint in endpoints:
            print(f"  {endpoint['path']} - Status: {endpoint['status']}")

        vulns = enum.check_api_vulnerabilities()
        print("\nVulnerabilities:")
        for k, v in vulns.items():
            print(f"  {k}: {v}")

        enum.close()
