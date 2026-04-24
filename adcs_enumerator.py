import logging
from impacket.ldap import ldap as ldap_impacket

class ADCSEnumerator:
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
        
        if not domain:
            self.base_dn = ""
        else:
            self.base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
            
        self.logger = logging.getLogger('ADCSEnumerator')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def connect(self):
        protocol = "ldaps" if self.use_ssl else "ldap"
        url = f"{protocol}://{self.target}"
        self.logger.info(f"Connecting to {url} with base DN: {self.base_dn}")

        try:
            self.ldap_conn = ldap_impacket.LDAPConnection(url, self.base_dn, self.target)
            if self.username == '' and self.password == '' and self.nthash == '':
                self.ldap_conn.login('', '', '', '', '')
            else:
                self.ldap_conn.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.logger.info("Successfully connected via LDAP for ADCS enumeration.")
            return True
        except Exception as e:
            self.logger.error(f"ADCS LDAP Connection Error: {e}")
            return False

    def enumerate_cas(self):
        """Query LDAP for PKI Enrollment Services (Certificate Authorities)."""
        if not self.ldap_conn:
            return []

        self.logger.info("Enumerating Enterprise Certificate Authorities...")
        # Search for pKIEnrollmentService within the Configuration partition
        config_nc = f"CN=Configuration,{self.base_dn}"
        search_filter = "(objectCategory=pKIEnrollmentService)"
        attributes = ['cn', 'dNSHostName', 'cACertificate']
        
        cas = []
        try:
            # We must search from the Configuration naming context to find ADCS setup
            results = self.ldap_conn.search(searchBase=config_nc, searchFilter=search_filter, attributes=attributes, sizeLimit=0)
            from impacket.ldap import ldapasn1 as ldapasn1_impacket
            for entry in results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    ca_data = {str(attr['type']).lower(): str(attr['vals'][0]) for attr in entry['attributes']}
                    name = ca_data.get('cn', 'Unknown')
                    dns = ca_data.get('dnshostname', 'Unknown')
                    cas.append({'name': name, 'dns': dns})
                    self.logger.info(f"Found Certificate Authority: {name} on {dns}")
            return cas
        except Exception as e:
            self.logger.error(f"Error enumerating CAs: {e}")
            return cas

    def enumerate_templates(self):
        """Query LDAP for vulnerable/published Certificate Templates."""
        if not self.ldap_conn:
            return []

        self.logger.info("Enumerating Certificate Templates...")
        config_nc = f"CN=Configuration,{self.base_dn}"
        search_filter = "(objectCategory=pKICertificateTemplate)"
        attributes = ['cn', 'displayName', 'pKIExtendedKeyUsage', 'msPKI-Enrollment-Flag']
        
        templates = []
        try:
            results = self.ldap_conn.search(searchBase=config_nc, searchFilter=search_filter, attributes=attributes, sizeLimit=0)
            from impacket.ldap import ldapasn1 as ldapasn1_impacket
            for entry in results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    t_data = {}
                    for attr in entry['attributes']:
                        attr_type = str(attr['type']).lower()
                        vals = [str(v) for v in attr['vals']]
                        t_data[attr_type] = vals[0] if len(vals) == 1 else vals
                        
                    name = t_data.get('cn', 'Unknown')
                    ekus = t_data.get('pkiextendedkeyusage', [])
                    
                    # Highlight Client Authentication templates which might be vulnerable to ESC1/ESC8
                    client_auth = '1.3.6.1.5.5.7.3.2' in ekus if isinstance(ekus, list) else '1.3.6.1.5.5.7.3.2' == ekus
                    if client_auth:
                        self.logger.warning(f"Found Client Auth Template: {name} (Potential ESC1 candidate if ENROLLEE_SUPPLIES_SUBJECT is true)")
                    else:
                        self.logger.info(f"Found Template: {name}")
                        
                    templates.append({'name': name, 'client_auth': client_auth})
            return templates
        except Exception as e:
            self.logger.error(f"Error enumerating Templates: {e}")
            return templates

    def close(self):
        if self.ldap_conn:
            self.ldap_conn.close()
