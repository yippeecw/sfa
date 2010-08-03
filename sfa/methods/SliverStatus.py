from sfa.util.faults import *
from sfa.util.namespace import *
from sfa.util.method import Method
from sfa.util.parameter import Parameter

class SliverStatus(Method):
    """
    Get the status of a sliver
    
    @param slice_urn (string) URN of slice to allocate to
    
    """
    interfaces = ['aggregate', 'slicemgr', 'component', 'geni_am']
    accepts = [
        Parameter(str, "Slice URN"),
        Mixed(Parameter(str, "Credential string"),
              Parameter(type([str]), "List of credentials")),
        ]
    returns = Parameter(dict, "Status details")

    def call(self, slice_xrn, creds):
        hrn, type = urn_to_hrn(slice_xrn)
        valid_creds = self.api.auth.checkCredentials(creds, 'sliverstatus', hrn)

        self.api.logger.info("interface: %s\ttarget-hrn: %s\tmethod-name: %s"%(self.api.interface, hrn, self.name))
    
        manager = self.api.get_interface_manager()
        status = manager.delete_slice(self.api, xrn, valid_creds)

        return status
    
