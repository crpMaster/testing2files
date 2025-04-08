from easysnmp import Session
import socket
import time

class SNMPScanner:
    def __init__(self, ip_address, username, auth_protocol, auth_password, priv_protocol, priv_password, port=161):
        self.ip_address = ip_address
        self.port = port
        self.username = username
        self.auth_protocol = auth_protocol.lower()
        self.auth_password = auth_password
        self.priv_protocol = priv_protocol.lower()
        self.priv_password = priv_password
        
        # Create SNMP session
        self.session = Session(
            hostname=ip_address,
            version=3,
            security_level='authPriv',
            security_username=username,
            auth_protocol=self.auth_protocol,
            auth_password=auth_password,
            privacy_protocol=self.priv_protocol,
            privacy_password=priv_password,
            port=port
        )
        
        # Common OIDs for system information
        self.system_oids = {
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysObjectID': '1.3.6.1.2.1.1.2.0',
            'sysUpTime': '1.3.6.1.2.1.1.3.0',
            'sysContact': '1.3.6.1.2.1.1.4.0',
            'sysName': '1.3.6.1.2.1.1.5.0',
            'sysLocation': '1.3.6.1.2.1.1.6.0',
            'sysServices': '1.3.6.1.2.1.1.7.0'
        }
        
        # Additional OIDs for network information
        self.network_oids = {
            'ifNumber': '1.3.6.1.2.1.2.1.0',
            'ifTable': '1.3.6.1.2.1.2.2'
        }
    
    def _snmp_get(self, oid):
        """Perform SNMP GET operation for a single OID"""
        try:
            result = self.session.get(oid)
            return {'oid': result.oid, 'value': result.value}
        except Exception as e:
            return {'error': str(e)}
    
    def _snmp_walk(self, oid):
        """Perform SNMP WALK operation starting from a base OID"""
        try:
            results = self.session.walk(oid)
            return [{'oid': item.oid, 'value': item.value} for item in results]
        except Exception as e:
            return {'error': str(e)}
    
    def check_connectivity(self):
        """Check if the device is reachable via SNMP"""
        try:
            # First try a simple ping
            socket.setdefaulttimeout(1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.ip_address, self.port))
            s.close()
            
            # Then try a simple SNMP get
            result = self._snmp_get(self.system_oids['sysName'])
            if 'error' in result:
                return False
            return True
        except:
            return False
    
    def get_system_info(self):
        """Get basic system information via SNMP"""
        system_info = {}
        for name, oid in self.system_oids.items():
            result = self._snmp_get(oid)
            system_info[name] = result
        return system_info
    
    def get_interfaces(self):
        """Get network interfaces information"""
        return self._snmp_walk(self.network_oids['ifTable'])
    
    def scan(self):
        """Perform a complete scan of the device"""
        start_time = time.time()
        
        # Check if device is reachable
        if not self.check_connectivity():
            return {
                'status': 'error',
                'message': f'Device {self.ip_address} is not reachable via SNMP'
            }
        
        # Get system information
        system_info = self.get_system_info()
        
        # Get network interfaces
        interfaces = self.get_interfaces()
        
        # Calculate scan duration
        duration = time.time() - start_time
        
        return {
            'status': 'success',
            'ip_address': self.ip_address,
            'duration': f"{duration:.2f} seconds",
            'system_info': system_info,
            'interfaces': interfaces
        } 