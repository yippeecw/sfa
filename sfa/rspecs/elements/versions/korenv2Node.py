from sfa.util.xrn import Xrn, get_leaf
from sfa.util.xml import XpathFilter
from sfa.rspecs.elements.openstackv2 import OSNode
from sfa.rspecs.elements.versions.korenv2SliverType import Korenv2SliverType
from sfa.rspecs.elements.granularity import Granularity

class Korenv2Node:

    @staticmethod
    def add_nodes(xml, nodes, rspec_content_type='openstack'):
        node_elems=[]
        for node in nodes:
            node_fields = OSNode()
            node_fields.pop('slivers')
            node_elem = xml.add_instance(('{%s}node' % xml.namespaces['openstack']), node, node_fields)
            # For Advertisement Rspec
            if node.get('name') == 'advertisement':
                Korenv2SliverType.add_slivers(node_elem, node.get('slivers'))
            # For Manifest Rspec
            else:
                Korenv2SliverType.add_hot_slivers(node_elem, node.get('slivers'))
            node_elems.append(node_elem)
        return node_elems
                
    @staticmethod
    def get_nodes(xml, filter=None):
        if filter is None: filter={}
        xpath = '//openstack:node%s | //default:node%s' % (XpathFilter.xpath(filter), XpathFilter.xpath(filter))
#        xpath = '//node%s | //default:node%s' % (XpathFilter.xpath(filter), XpathFilter.xpath(filter))
        node_elems = xml.xpath(xpath)
        return Korenv2Node.get_node_objs(node_elems)

    @staticmethod
    def get_nodes_with_slivers(xml, filter=None):
        if filter is None: filter={}
        xpath = '//openstack:node[count(openstack:sliver)>0] | //default:node[count(sliver) > 0]'
#        xpath = '//node[count(sliver)>0] | //default:node[count(openstack:sliver) > 0]' 
        node_elems = xml.xpath(xpath)        
        return Korenv2Node.get_node_objs(node_elems) 

    @staticmethod
    def get_node_objs(node_elems):
        nodes=[]
        for node_elem in node_elems:
            node = OSNode(node_elem.attrib, node_elem)
            # Get Openstack nodes for advertisement Rspec
            if node_elem.get_instance()['name'] == 'advertisement':
                node['slivers'] = Korenv2SliverType.get_ad_slivers(node_elem)
            else:
                # Get Openstack nodes for request Rspec
                node['slivers'] = Korenv2SliverType.get_req_slivers(node_elem)
            nodes.append(node)
        return nodes

if __name__ == '__main__':
    r = RSpec('/tmp/koren_node.rspec')
    r2 = RSpec(version = 'KOREN')
    nodes = Korenv2Node.get_nodes(r.xml)
    Korenv2Node.add_nodes(r2.xml.root, nodes)
