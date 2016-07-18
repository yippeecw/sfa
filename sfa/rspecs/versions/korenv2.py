from copy import deepcopy
from lxml import etree

from StringIO import StringIO
from sfa.util.xrn import Xrn
from sfa.util.sfalogging import logger
from sfa.rspecs.rspec import RSpec
from sfa.rspecs.version import RSpecVersion
from sfa.rspecs.elements.versions.korenv2Node import Korenv2Node

class KORENv2(RSpecVersion):
    type = 'KOREN'
    content_type = 'ad'
    version = '2'
    schema = 'http://203.255.254.100:8888/resources/sfa/rspecs/openstack/3/os-hot_ad.xsd'
    namespace = 'openstack'
    extensions = {
        'openstack': 'http://203.255.254.100:8888/resources/sfa/rspecs/openstack/3',
#        'flack': "http://www.protogeni.net/resources/rspec/ext/flack/1",
#        'planetlab': "http://www.planet-lab.org/resources/sfa/ext/planetlab/1",
#        'plos': "http://www.planet-lab.org/resources/sfa/ext/plos/1"
    }   
    namespaces = dict(extensions.items() + [('default', namespace)])
    elements = []

    def merge(self, in_rspec):
        # just copy over all the child elements under the root element
        if isinstance(in_rspec, RSpec):
            rspec = in_rspec
        else:
            rspec = RSpec(in_rspec)

        nodes = rspec.version.get_nodes()
        for node in nodes:
            self.xml.append(node.element)

    def get_nodes(self, filter=None):
        return Korenv2Node.get_nodes(self.xml, filter)

    def get_nodes_with_slivers(self):
        return Korenv2Node.get_nodes_with_slivers(self.xml)

    def add_nodes(self, nodes, check_for_dupes=False, rspec_content_type=None):
        return Korenv2Node.add_nodes(self.xml, nodes, rspec_content_type)
    

class KORENv2Ad(KORENv2):
    enabled = True
    content_type = 'ad'
    schema = 'http://203.255.254.100:8888/resources/sfa/rspecs/openstack/3/os-hot_ad.xsd'
    template = '<rspec type="advertisement" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.geni.net/resources/rspec/3" xmlns:openstack="http://203.255.254.100:8888/resources/sfa/rspecs/openstack/3" xsi:schemaLocation="http://www.geni.net/resources/rspec/3/ad.xsd http://203.255.254.100:8888/resources/sfa/rspecs/openstack/3/os-hot_ad.xsd"/>'

class KORENv2Request(KORENv2):
    enabled = True
    content_type = 'request'
    schema = 'http://203.255.254.100:8888/resources/sfa/rspecs/openstack/3/os-hot.xsd'
    template = '<rspec type="request" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.geni.net/resources/rspec/3" xmlns:openstack="http://203.255.254.100:8888/resources/sfa/rspecs/openstack/3" xsi:schemaLocation="http://www.geni.net/resources/rspec/3/request.xsd http://203.255.254.100:8888/resources/sfa/rspecs/openstack/3/os-hot.xsd"/>'

class KORENv2Manifest(KORENv2):
    enabled = True
    content_type = 'manifest'
    schema = 'http://203.255.254.100:8888/resources/sfa/rspecs/openstack/3/os-hot.xsd'
    template = '<rspec type="manifest" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.geni.net/resources/rspec/3" xmlns:openstack="http://203.255.254.100:8888/resources/sfa/rspecs/openstack/3" xsi:schemaLocation="http://www.geni.net/resources/rspec/3/manifest.xsd http://203.255.254.100:8888/resources/sfa/rspecs/openstack/3/os-hot.xsd"/>'

if __name__ == '__main__':
    from sfa.rspecs.rspec_elements import *
    print "=============================="
    print "Call Main with Rspec for KOREN"
    print "=============================="
    r = RSpec('/tmp/koren.rspec')
    r.load_rspec_elements(Korenv2.elements)
    r.namespaces = Korenv2.namespaces
    print r.get(RSpecElements.NODE)
