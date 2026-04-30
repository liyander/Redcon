import logging
from impacket.ldap import ldap as ldap_impacket
# test
class LDAPEnumerator:
    def __init__(self, target, domain='', username='', password='', lmhash='', nthash='', port=389, use_ssl=False):
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.port = port if not use_ssl else 636
        self.use_ssl = use_ssl
        self.ldap_conn = None
        self.base_dn = self._build_base_dn(domain)
        
        # Configure logging
        self.logger = logging.getLogger('LDAPEnumerator')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def _build_base_dn(self, domain):
        if not domain:
            return ""
        return ','.join([f"DC={part}" for part in domain.split('.')])

    def connect(self):
        """Establish LDAP/LDAPS connection to the target."""
        protocol = "ldaps" if self.use_ssl else "ldap"
        url = f"{protocol}://{self.target}"
        self.logger.info(f"Connecting to {url} with base DN: {self.base_dn}")

        try:
            # We use target as dns_server equivalent if not specified otherwise
            self.ldap_conn = ldap_impacket.LDAPConnection(url, self.base_dn, self.target)
            
            if self.username == '' and self.password == '' and self.nthash == '':
                self.logger.info("Attempting anonymous LDAP bind (Simple)...")
                try:
                    self.ldap_conn.login('', '', authenticationChoice='simple')
                except TypeError:
                    self.ldap_conn.login('', '', '', '', '')
            else:
                self.logger.info(f"Authenticating as {self.domain}\\{self.username}...")
                try:
                    self.ldap_conn.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
                except Exception as e:
                    self.logger.warning(f"Primary authentication failed: {e}")
                    self.logger.info("Falling back to Simple Bind (like ldapsearch -x)...")
                    try:
                        # Attempt Simple Bind using Impacket
                        bind_dn = self.username
                        if self.domain and '\\' not in bind_dn and '@' not in bind_dn:
                            bind_dn = f"{self.domain}\\{self.username}"
                        self.ldap_conn.login(bind_dn, self.password, authenticationChoice='simple')
                    except TypeError:
                        # Some versions of impacket don't take authenticationChoice directly here or expect simple bind differently
                        self.ldap_conn.login(bind_dn, self.password, '','')
                    except Exception as fallback_e:
                        self.logger.warning(f"Simple Bind fallback failed: {fallback_e}")
                        self.logger.info("Falling back to Anonymous Bind (Simple)...")
                        try:
                            self.ldap_conn.login('', '', authenticationChoice='simple')
                        except TypeError:
                            self.ldap_conn.login('', '', '', '', '')

            self.logger.info("Successfully connected and authenticated via LDAP.")
            
            # Automatically discover base_dn if empty
            if not self.base_dn:
                self.logger.info("Base DN not provided. Attempting to discover defaultNamingContext...")
                try:
                    from impacket.ldap import ldapasn1 as ldapasn1_impacket
                    # Root DSE must be queried with base object scope (searchScope=0)
                    try:
                        # Correct positional args for Impacket LDAPConnection.search:
                        # searchFilter, attributes=None, searchBase=None, searchScope=2, sizeLimit=0
                        res = self.ldap_conn.search(searchFilter='(objectClass=*)', attributes=['namingContexts', 'defaultNamingContext'], searchBase='', searchScope=0, sizeLimit=0)
                    except TypeError as e:
                        if "exceptions must derive" in str(e):
                            raise e
                        # Fallback for different parameter order just in case
                        res = self.ldap_conn.search(searchFilter='(objectClass=*)', attributes=['namingContexts', 'defaultNamingContext'], searchBase='')
                    for entry in res:
                        if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                            for attr in entry['attributes']:
                                if str(attr['type']).lower() in ['namingcontexts', 'defaultnamingcontext']:
                                    self.base_dn = str(attr['vals'][0])
                                    self.logger.info(f"Discovered Base DN: {self.base_dn}")
                                    # Try setting it if the library supports it
                                    if hasattr(self.ldap_conn, '_baseDN'):
                                        self.ldap_conn._baseDN = self.base_dn
                                    elif hasattr(self.ldap_conn, 'baseDN'):
                                        self.ldap_conn.baseDN = self.base_dn
                                    break
                except TypeError as e:
                    if "exceptions must derive from BaseException" in str(e) or "coerc" in str(e):
                        self.logger.warning("Failed to discover Base DN automatically (Server block/Impacket error).")
                    else:
                        self.logger.warning(f"Failed to discover Base DN automatically (TypeError): {e}")
                except Exception as e:
                    if "PyAsn1Error" in str(type(e)) or "coerc" in str(e):
                        self.logger.warning("Failed to discover Base DN automatically (PyAsn1 format mismatch).")
                    else:
                        self.logger.warning(f"Failed to discover Base DN automatically: {e}")
                        
                # CLI fallback for base DN discovery if empty
                if not self.base_dn:
                    import subprocess
                    try:
                        self.logger.info("Attempting CLI fallback (ldapsearch) to map naming contexts...")
                        cmd = ['ldapsearch', '-x', '-H', f'ldap://{self.target}', '-b', '', '-s', 'base', 'namingContexts']
                        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=5).decode(errors='ignore')
                        for line in out.split('\n'):
                            if line.lower().startswith('namingcontexts:'):
                                self.base_dn = line.split(':', 1)[1].strip()
                                self.logger.info(f"Discovered Base DN via ldapsearch: {self.base_dn}")
                                if hasattr(self.ldap_conn, '_baseDN'): self.ldap_conn._baseDN = self.base_dn
                                elif hasattr(self.ldap_conn, 'baseDN'): self.ldap_conn.baseDN = self.base_dn
                                break
                    except Exception as e:
                        self.logger.warning(f"CLI Base DN fallback failed: {e}")

            return True

        except ldap_impacket.LDAPSessionError as e:
            if "strongerAuthRequired" in str(e) and not self.use_ssl:
                self.logger.warning("LDAP error: strongerAuthRequired. Target likely requires LDAPS.")
            else:
                self.logger.error(f"LDAP Session Error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Connection Error: {e}")
            return False

    def enumerate_users(self):
        """Query LDAP for all user accounts."""
        if not self.ldap_conn:
            self.logger.error("No active LDAP connection.")
            return []

        self.logger.info("Enumerating domain users...")
        search_filter = "(objectClass=person)"
        attributes = ['sAMAccountName', 'description', 'userAccountControl', 'cn']
        
        users = []
        try:
            results = self.ldap_conn.search(searchFilter=search_filter, attributes=attributes, searchBase=self.base_dn, sizeLimit=0)
            from impacket.ldap import ldapasn1 as ldapasn1_impacket
            for entry in results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    user_data = {str(attr['type']).lower(): str(attr['vals'][0]) for attr in entry['attributes']}
                    # Default values
                    username = user_data.get('samaccountname', user_data.get('cn', 'Unknown'))
                    description = user_data.get('description', '')
                    users.append({'username': username, 'description': description})
                    self.logger.info(f"Found User: {username} - {description}")
            return users
        except TypeError as e:
            if "exceptions must derive from BaseException" in str(e):
                self.logger.error("LDAP search failed: The server likely rejected the query (e.g., anonymous access denied). [Impacket Error]")
                self._fallback_enumerate_users(users)
            else:
                self.logger.error(f"Type Error enumerating users: {e}")
            return users
        except Exception as e:
            if "PyAsn1Error" in str(type(e)) or "coerc" in str(e):
                self.logger.error(f"PyAsn1 format mismatch enumerating users.")
                self._fallback_enumerate_users(users)
            else:
                self.logger.error(f"Error enumerating users: {e}")
            return users

    def _fallback_enumerate_users(self, users):
        import subprocess
        try:
            self.logger.info("Attempting CLI fallback (ldapsearch) to enumerate users...")
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{self.target}']
            if self.base_dn:
                cmd.extend(['-b', self.base_dn])
            cmd.append('(objectClass=person)')
            
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=10).decode(errors='ignore')
            current_user = {}
            for line in out.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    if current_user and current_user.get('username'):
                        users.append(current_user)
                        current_user = {}
                    continue
                if ': ' in line:
                    k, v = line.split(': ', 1)
                    if k.lower() in ('uid', 'cn', 'samaccountname'):
                        current_user['username'] = v
                        if k.lower() == 'uid': # Prefer uid if available
                            current_user['username_uid'] = v
                    elif k.lower() in ('description', 'title'):
                        current_user['description'] = v
            if current_user and current_user.get('username'):
                users.append(current_user)
            
            for u in users:
                if 'username_uid' in u:
                    u['username'] = u.pop('username_uid')
                u.setdefault('description', '')
                self.logger.info(f"Found User (CLI): {u.get('username')} - {u.get('description')}")
        except Exception as e:
            self.logger.error(f"CLI User enumeration fallback failed: {e}")

    def get_whoami_info(self, target_user=None):
        """Get detailed LDAP properties of the authenticated user or a specific user."""
        if not self.ldap_conn:
            self.logger.error("No active LDAP connection.")
            return None
            
        username_to_search = target_user if target_user else self.username
        if not username_to_search:
            self.logger.error("Cannot query whoami without a username to search.")
            return None

        self.logger.info(f"Querying detailed AD properties for user: {username_to_search}...")
        search_filter = f"(&(objectClass=person)(|(sAMAccountName={username_to_search})(cn={username_to_search})))"
        attributes = [
            "name", "sAMAccountName", "description", "distinguishedName",
            "pwdLastSet", "lastLogon", "userAccountControl", "servicePrincipalName",
            "userPrincipalName", "objectSid", "mail", "badPwdCount", "memberOf"
        ]
        
        try:
            results = self.ldap_conn.search(searchFilter=search_filter, attributes=attributes, searchBase=self.base_dn, sizeLimit=0)
            from impacket.ldap import ldapasn1 as ldapasn1_impacket
            
            for entry in results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    user_params = {}
                    for attr in entry['attributes']:
                        attr_type = str(attr['type'])
                        vals = [str(v) for v in attr['vals']]
                        user_params[attr_type] = vals[0] if len(vals) == 1 else vals
                    return user_params
            
            self.logger.warning(f"No user found matching sAMAccountName={username_to_search}")
            return None
        except TypeError as e:
            if "exceptions must derive from BaseException" in str(e):
                self.logger.error("LDAP search failed: The server likely rejected the query (e.g., anonymous access denied). [Impacket Error]")
            else:
                self.logger.error(f"Type Error querying whoami: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error querying whoami for {username_to_search}: {e}")
            return None

    def enumerate_computers(self):
        """Query LDAP for all computer objects."""
        if not self.ldap_conn:
            self.logger.error("No active LDAP connection.")
            return []

        self.logger.info("Enumerating domain computers...")
        search_filter = "(objectClass=computer)"
        attributes = ['sAMAccountName', 'dNSHostName']
        
        computers = []
        try:
            results = self.ldap_conn.search(searchFilter=search_filter, attributes=attributes, searchBase=self.base_dn, sizeLimit=0)
            from impacket.ldap import ldapasn1 as ldapasn1_impacket
            for entry in results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    comp_data = {str(attr['type']).lower(): str(attr['vals'][0]) for attr in entry['attributes']}
                    name = comp_data.get('samaccountname', 'Unknown')
                    dns_name = comp_data.get('dnshostname', '')
                    computers.append({'name': name, 'dns_name': dns_name})
                    self.logger.info(f"Found Computer: {name} (DNS: {dns_name})")
            return computers
        except TypeError as e:
            if "exceptions must derive from BaseException" in str(e):
                self.logger.error("LDAP search failed: The server likely rejected the query (e.g., anonymous access denied). [Impacket Error]")
            else:
                self.logger.error(f"Type Error enumerating computers: {e}")
            return computers
        except Exception as e:
            self.logger.error(f"Error enumerating computers: {e}")
            return computers

    def enumerate_asrep_roastable(self):
        """Query LDAP for users who do not require Kerberos pre-authentication (AS-REP Roastable)."""
        if not self.ldap_conn:
            self.logger.error("No active LDAP connection.")
            return []

        self.logger.info("Enumerating AS-REP Roastable users (DONT_REQUIRE_PREAUTH)...")
        # UF_DONT_REQUIRE_PREAUTH = 4194304
        search_filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        attributes = ['sAMAccountName', 'userPrincipalName']
        
        users = []
        try:
            results = self.ldap_conn.search(searchFilter=search_filter, attributes=attributes, searchBase=self.base_dn, sizeLimit=0)
            from impacket.ldap import ldapasn1 as ldapasn1_impacket
            for entry in results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    user_data = {str(attr['type']).lower(): str(attr['vals'][0]) for attr in entry['attributes']}
                    username = user_data.get('samaccountname', 'Unknown')
                    upn = user_data.get('userprincipalname', '')
                    users.append({'username': username, 'upn': upn})
                    self.logger.highlight(f"VULNERABLE AS-REP ROASTABLE USER IDENTIFIED: {username} ({upn})") if hasattr(self.logger, 'highlight') else self.logger.error(f"AS-REP ROASTABLE USER: {username} ({upn})")
            return users
        except TypeError as e:
            if "exceptions must derive from BaseException" in str(e):
                self.logger.error("LDAP search failed: The server likely rejected the query (e.g., anonymous access denied). [Impacket Error]")
            else:
                self.logger.error(f"Type Error enumerating AS-REP roastable users: {e}")
            return users
        except Exception as e:
            self.logger.error(f"Error enumerating AS-REP roastable users: {e}")
            return users

    def close(self):
        """Close the LDAP connection."""
        if self.ldap_conn:
            self.ldap_conn.close()
            self.logger.info("LDAP connection closed.")

if __name__ == '__main__':
    # Test execution example
    enum = LDAPEnumerator('127.0.0.1', domain='test.local', username='guest', password='')
    if enum.connect():
        enum.enumerate_users()
        enum.close()
