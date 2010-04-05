
### $URL: https://svn.planet-lab.org/svn/sfa/trunk/sfa/methods/reset_slices.py $

from sfa.util.faults import *
from sfa.util.method import Method
from sfa.util.parameter import Parameter, Mixed
from sfa.trust.auth import Auth
from sfa.trust.credential import Credential

class get_trusted_certs(Method):
    """
    @param cred credential string specifying the rights of the caller
    @return list of gid strings  
    """

    interfaces = ['registry']
    
    accepts = [
        Mixed(Parameter(str, "Credential string"),
              Parameter(None, "Credential not specified"))
        ]

    returns = Parameter([str], "List of GID strings")
    
    def call(self, cred = None):
        # If cred is not specified just return the gid for this interface.
        # This is true when when a peer is attempting to initiate federation
        # with this interface 
        if not cred:
            gid_strings = []
            for gid in self.api.auth.trusted_cert_list:
                if gid.get_hrn() == self.api.config.SFA_INTERFACE_HRN:
                    gid_strings.append[gid.save_to_string(save_parents=True)]   
            return gid_strings

        # authenticate the cred
        self.api.auth.check(cred, 'gettrustedcerts')
        gid_strings = [gid.save_to_string(save_parents=True) for \
                                gid in self.api.auth.trusted_cert_list] 
        
        return gid_strings 
