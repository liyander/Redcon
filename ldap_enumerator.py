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
                self.logger.info("Attempting anonymous LDAP bind...")
                self.ldap_conn.login('', '', '', '', '')
            else:
                self.logger.info(f"Authenticating as {self.domain}\\{self.username}...")
                self.ldap_conn.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            
            self.logger.info("Successfully connected and authenticated via LDAP.")
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
        search_filter = "(&(objectCategory=person)(objectClass=user))"
        attributes = ['sAMAccountName', 'description', 'userAccountControl']
        
        users = []
        try:
            results = self.ldap_conn.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)
            from impacket.ldap import ldapasn1 as ldapasn1_impacket
            for entry in results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    user_data = {str(attr['type']).lower(): str(attr['vals'][0]) for attr in entry['attributes']}
                    # Default values
                    username = user_data.get('samaccountname', 'Unknown')
                    description = user_data.get('description', '')
                    users.append({'username': username, 'description': description})
                    self.logger.info(f"Found User: {username} - {description}")
            return users
        except Exception as e:
            self.logger.error(f"Error enumerating users: {e}")
            return users

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
        search_filter = f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={username_to_search}))"
        attributes = [
            "name", "sAMAccountName", "description", "distinguishedName",
            "pwdLastSet", "lastLogon", "userAccountControl", "servicePrincipalName",
            "userPrincipalName", "objectSid", "mail", "badPwdCount", "memberOf"
        ]
        
        try:
            results = self.ldap_conn.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)
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
            results = self.ldap_conn.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)
            from impacket.ldap import ldapasn1 as ldapasn1_impacket
            for entry in results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    comp_data = {str(attr['type']).lower(): str(attr['vals'][0]) for attr in entry['attributes']}
                    name = comp_data.get('samaccountname', 'Unknown')
                    dns_name = comp_data.get('dnshostname', '')
                    computers.append({'name': name, 'dns_name': dns_name})
                    self.logger.info(f"Found Computer: {name} (DNS: {dns_name})")
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
            results = self.ldap_conn.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)
            from impacket.ldap import ldapasn1 as ldapasn1_impacket
            for entry in results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    user_data = {str(attr['type']).lower(): str(attr['vals'][0]) for attr in entry['attributes']}
                    username = user_data.get('samaccountname', 'Unknown')
                    upn = user_data.get('userprincipalname', '')
                    users.append({'username': username, 'upn': upn})
                    self.logger.highlight(f"VULNERABLE AS-REP ROASTABLE USER IDENTIFIED: {username} ({upn})") if hasattr(self.logger, 'highlight') else self.logger.error(f"AS-REP ROASTABLE USER: {username} ({upn})")
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
