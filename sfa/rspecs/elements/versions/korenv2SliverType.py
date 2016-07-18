from sfa.rspecs.elements.element import Element
from sfa.rspecs.elements.openstackv2 import *
from sfa.util.sfalogging import logger
import types
from uuid import UUID

def is_uuid(uuid_string):
    try:
        check = UUID(uuid_string, version=4)
    except ValueError:
        return False
    return check.hex == uuid_string.replace('-','')

class Korenv2SliverType:

    @staticmethod
    def add_slivers(xml, slivers):
        if not slivers:
            return None 
        if not isinstance(slivers, list):
            slivers = [slivers]
        # OS::Nova::Server Resources for AD Rspec
        for sliver in slivers:
            sliver_fields = ['name']
            sliver_elem = xml.add_element('{%s}sliver' % xml.namespaces['openstack'])
            for field in sliver_fields:
                if ("".join(sliver.keys())) == 'OSNovaServer':
                    sliver_elem.set(field, str('OSNovaServer'))
            
            osnovaserver = sliver['OSNovaServer']

            # List of images
            image_fields = ['name', 'id', 'minDisk', 'minRam']
            images = osnovaserver.get('images')
            for image in images:
                sliver_elem.add_instance('{%s}images' % xml.namespaces['openstack'], image, image_fields)
            
            # List of flavors
            flavor_fields = ['name', 'id', 'vcpus', 'ram', 'disk']
            flavors = osnovaserver.get('flavors')
            for flavor in flavors:
                sliver_elem.add_instance('{%s}flavors' % xml.namespaces['openstack'], flavor, flavor_fields)

            # List of availability_zones
            availability_zones_fields = ['zone']
            availability_zones = osnovaserver.get('availability_zones')
            for availability_zone in availability_zones:
                sliver_elem.add_instance('{%s}availability_zones' % xml.namespaces['openstack'], \
                                         availability_zone, availability_zones_fields)

            # List of security_groups
            security_groups_fields = ['group', 'description']
            security_groups = osnovaserver.get('security_groups')
            for security_group in security_groups:
                secgrp_sliver_elem = sliver_elem.add_instance('{%s}security_groups' % xml.namespaces['openstack'], \
                                                              security_group, security_groups_fields)
                if security_group.get('rules'):
                    rule_fields = ['to_port', 'from_port', 'ip_protocol', 'ip_range']
                    for rule in security_group.get('rules'):
                        secgrp_sliver_elem.add_instance('{%s}rules' % xml.namespaces['openstack'], rule, rule_fields)

        #        sliver_elem = xml.add_element('{%s}sliver' % xml.namespaces['openstack'])
        #        return Korenv2SliverType.get_sliver_nodes(sliver_elem, slivers, OSSliver)

    @staticmethod
    def add_hot_slivers(xml, slivers):
        if not slivers: return None
        if not isinstance(slivers, list): slivers=[slivers]
        for sliver in slivers:
            sliver_fields = sliver.get('resources').keys()
            for field in sliver_fields:
                sliver_elem = xml.add_element('{%s}sliver' % xml.namespaces['openstack'])
                sliver_elem.set(str('name'), field)
                sliver_elem.set(str('type'), sliver.get('resources')[field].get('type'))
                sliver_elem.add_instance('{%s}properties' % xml.namespaces['openstack'], \
                                         sliver.get('resources')[field].get('properties'), \
                                         sliver.get('resources')[field].get('properties').keys())

    @staticmethod
    def get_sliver_nodes(xml, slivers, OSNodeClass=None, fields=None):
        if len(slivers) == 0: 
            return None
        if fields==None: fields = OSNodeClass.fields

        if isinstance(slivers, list):
            pass
        elif isinstance(slivers, dict):
            slivers = [slivers]
        else:
            logger.error("Not supported by %s" % slivers)
            raise Exception(slivers)

        for sliver in slivers:
            for key, value in sliver.items():
                try:
                    if value:
                        if isinstance(fields[key], type):
                            os_elem = xml.add_element('{%s}%s' % (xml.namespaces['openstack'], key))
                            Korenv2SliverType.get_os_sliver_nodes(xml=os_elem, 
                                                                  slivers=value, 
                                                                  OSNodeClass=fields[key])
                        elif isinstance(fields[key], types.DictType):
                            os_elem = xml.add_element('{%s}%s' % (xml.namespaces['openstack'], key))
                            if fields[key]['class']:
                                Korenv2SliverType.get_os_sliver_nodes(os_elem, value, None, 
                                                                      fields[key]['fields'])
                            else:
                                Korenv2SliverType.get_os_sliver_nodes(os_elem, [value], None, 
                                                                      fields[key]['fields'])
                        elif isinstance(fields[key], types.StringType):
                            if fields[key] == 'get_resource':
                                if value.get('get_resource'):
                                    xml.set(key, value['get_resource'])
                                else:
                                    xml.set(key, value)
                            elif fields[key] == 'simple_list':
                                for v in value:
                                    os_elem = xml.add_element('{%s}%s' % (xml.namespaces['openstack'], key))
                                    os_elem.set('value', v)
                        else:
                            xml.set(key, value)
                except Exception, e:
                    if isinstance(value, str) and (str(value) is not '0'):
                        value = eval(value)
                        sub_elem = os_elem.add_instance('{%s}%s' % (xml.namespaces['openstack'], key), key, fields[key])
                        # For ip_range: one of the rule item in security_groups
                        if isinstance(value, dict) and bool(value):
                            for k, v in value.items():
                                sub_elem.set(k, v)
                        else:
                            sub_elem.set('cidr', 'None')

                    elif isinstance(value, list):
                        # For images of Glance to use VM
                        os_elem = xml.add_element('{%s}%s' % (xml.namespaces['openstack'], key))
                        for i in value:
                            sub_elem = os_elem.add_instance('{%s}%s' % (os_elem.namespaces['openstack'], 'image'), \
                                                            key, fields[key])
                            for k, v in i.items():
                                sub_elem.set(k, v)
                    else:
                        logger.warn("[EXCEPT VALUE] %s,  tag: %s, value: %s in get_os_sliver_nodes" % (e, str(key), str(value)))

    @staticmethod
    def get_ad_slivers(xml, filter=None):
        if filter is None: filter={}
        sliver_elems = xml.xpath('./openstack:sliver')
        return sliver_elems

    @staticmethod
    def get_req_slivers(xml, filter=None):
        import json
        if filter is None: filter={}
        node_attrib = xml.attrib
        hot = { 'heat_template_version':node_attrib['heat_template_version'],
                'description': {'component_id': node_attrib['component_id']}
        }
        sliver_elems = xml.xpath('./openstack:sliver')
        resources = Korenv2SliverType.convert_rspec_to_hot(sliver_elems, hot['heat_template_version'])
        hot['resources'] = resources
        hot_json = json.loads(json.dumps(hot))
        return hot_json 

    @staticmethod
    def check_is_hot(type_name, rsc_dict):
        # OS::Nova::Server
        if type_name == 'OS::Nova::Server':
            if 'networks' in rsc_dict:
                for network in rsc_dict['networks']:
                    if network.get('port_extra_properties'):
                        network['port_extra_properties'] = network.get('port_extra_properties')[0]
                    if network.get('network'):
                        network['network'] = {'get_resource' : network.get('network')}
                    if network.get('port'):
                        network['port'] = {'get_resource' : network.get('port')}
                    if network.get('subnet'):
                        network['subnet'] = {'get_resource' : network.get('subnet')}
            if 'security_groups' in rsc_dict:
                tmp=[]
                for group in rsc_dict['security_groups']:
                    tmp.append(group['group'])
                rsc_dict['security_groups'] = tmp
        # OS::Neutron::Net
        if type_name == 'OS::Neutron::Net':
            if 'dhcp_agent_ids' in rsc_dict:
                tmp=[]
                for id in rsc_dict['dhcp_agent_ids']:
                    tmp.append(id['id'])
                rsc_dict['dhcp_agent_ids'] = tmp
        # OS::Neutron::Subnet
        if type_name == 'OS::Neutron::Subnet':
            if 'dns_nameservers' in rsc_dict:
                tmp=[]
                for dns in rsc_dict['dns_nameservers']:
                    tmp.append(dns['server'])
                rsc_dict['dns_nameservers'] = tmp
            if rsc_dict.get('network'):
                rsc_dict['network'] = {'get_resource' : rsc_dict.get('network')}
            if rsc_dict.get('subnetpool'):
                rsc_dict['subnetpool'] = {'get_resource' : rsc_dict.get('subnetpool')}
        # OS::Neutron::Router
        if type_name == 'OS::Neutron::Router':
            if 'external_gateway_info' in rsc_dict:
                rsc_dict['external_gateway_info'] = rsc_dict['external_gateway_info'][0]
            if 'l3_agent_ids' in rsc_dict:
                tmp=[]
                for id in rsc_dict['l3_agent_ids']:
                    tmp.append(id['id'])
                rsc_dict['l3_agent_ids'] = tmp
        # OS::Neutron::RouterInterface
        if type_name == 'OS::Neutron::RouterInterface':
            if rsc_dict.get('router'):
                rsc_dict['router'] = {'get_resource' : rsc_dict.get('router')}
            if rsc_dict.get('port'):
                rsc_dict['port'] = {'get_resource' : rsc_dict.get('port')}
            if rsc_dict.get('subnet'):
                rsc_dict['subnet'] = {'get_resource' : rsc_dict.get('subnet')}
        # OS::Neutron::VPNService
        if type_name == 'OS::Neutron::VPNService':
            if rsc_dict.get('router'):
                rsc_dict['router'] = {'get_resource' : rsc_dict.get('router')}
            if rsc_dict.get('subnet'):
                rsc_dict['subnet'] = {'get_resource' : rsc_dict.get('subnet')}
        # OS::Neutron::IKEPolicy
        if type_name == 'OS::Neutron::IKEPolicy':
            if 'lifetime' in rsc_dict:
                rsc_dict['lifetime'] = rsc_dict['lifetime'][0]
        # OS::Neutron::IPsecPolicy
        if type_name == 'OS::Neutron::IPsecPolicy':
            if 'lifetime' in rsc_dict:
                rsc_dict['lifetime'] = rsc_dict['lifetime'][0]
        # OS::Neutron::IPsecSiteConnection
        if type_name == 'OS::Neutron::IPsecSiteConnection':
            if 'dpd' in rsc_dict:
                rsc_dict['dpd'] = rsc_dict['dpd'][0]
            if 'peer_cidrs' in rsc_dict:
                tmp=[]
                for cidr in rsc_dict['peer_cidrs']:
                    tmp.append(cidr['cidr'])
                rsc_dict['peer_cidrs'] = tmp
            if rsc_dict.get('ikepolicy_id'):
                rsc_dict['ikepolicy_id'] = {'get_resource' : rsc_dict.get('ikepolicy_id')}
            if rsc_dict.get('ipsecpolicy_id'):
                rsc_dict['ipsecpolicy_id'] = {'get_resource' : rsc_dict.get('ipsecpolicy_id')}
            if rsc_dict.get('vpnservice_id'):
                rsc_dict['vpnservice_id'] = {'get_resource' : rsc_dict.get('vpnservice_id')}
        # OS::Neutron::Firewall
        if type_name == 'OS::Neutron::Firewall':
            if rsc_dict.get('firewall_policy_id'):
                rsc_dict['firewall_policy_id'] = {'get_resource' : rsc_dict.get('firewall_policy_id')}
        # OS::Neutron::FirewallPolicy
        if type_name == 'OS::Neutron::FirewallPolicy':
            if 'firewall_rules' in rsc_dict:
                tmp=[]
                for rule in rsc_dict['firewall_rules']:
                    tmp.append(rule['rule'])
                rsc_dict['firewall_rules'] = tmp
        # OS::Neutron::LBaaS::Pool
        if type_name == 'OS::Neutron::LBaaS::Pool':
            if 'session_persistence' in rsc_dict:
                rsc_dict['session_persistence'] = rsc_dict['session_persistence'][0]
        # OS::Neutron::FloatingIP
        if type_name == 'OS::Neutron::FloatingIP':
            if rsc_dict.get('floating_network'):
                rsc_dict['floating_network'] = {'get_resource' : rsc_dict.get('floating_network')}
            if rsc_dict.get('port_id'):
                rsc_dict['port_id'] = {'get_resource' : rsc_dict.get('port_id')}
        # OS::Neutron::FloatingIPAssociation
        if type_name == 'OS::Neutron::FloatingIPAssociation':
            if rsc_dict.get('floatingip_id'):
                rsc_dict['floatingip_id'] = {'get_resource' : rsc_dict.get('floatingip_id')}
            if rsc_dict.get('port_id'):
                rsc_dict['port_id'] = {'get_resource' : rsc_dict.get('port_id')}
        # OS::Glance::Image
        if type_name == 'OS::Glance::Image':
            if 'tags' in rsc_dict:
                tmp=[]
                for tag in rsc_dict['tags']:
                    tmp.append(tag['tag'])
                rsc_dict['tags'] = tmp
            if rsc_dict.get('id'):
                rsc_dict['id'] = {'get_resource' : rsc_dict.get('id')}
        return rsc_dict

    @staticmethod
    def convert_rspec_to_hot(sliver_elems, hot_version):
        import random
        resources={}
        c=random.randint(10,10000)
        for sliver_elem in sliver_elems:
            tmp={}
            # Check what sliver type is
            s_type = sliver_elem.attrib['type']
            # Transform sliver type to function name
            s_func = s_type.replace('::','')

            if sliver_elem.xpath('%s:%s'%(sliver_elem.prefix,s_func)):
                rsc_elem = sliver_elem.xpath('%s:%s'%(sliver_elem.prefix,s_func))[0]
            else:
                rsc_elem = sliver_elem
            # Set a resource name in sliver
            if 'name' in rsc_elem.attrib:
                if not resources.has_key(rsc_elem.attrib['name']):
                    rsc_name = rsc_elem.attrib['name']
                else:
                    rsc_name = rsc_elem.attrib['name']+str(c)
                    c += 10
            # Set a sliver name
            else:
                if 'name' in sliver_elem.attrib:
                    if not resources.has_key(sliver_elem.attrib['name']):
                        rsc_name = sliver_elem.attrib['name']
                    else:
                        rsc_name = sliver_elem.attrib['name']+str(c)
                        c += 10
                else:
                    continue

            def todict(elem, ns_name):
                d = {}
                d.update(elem.attrib)
                for child in elem.iterchildren():
                    if ns_name in child.tag:
                        tag = child.tag.replace('{%s}'%ns_name, '')
                    else:
                        tag = child.tag
                    if not tag in d:
                        d[tag] = []
                    d[tag].append(todict(child, ns_name))
                return d
            rsc_dict = todict(rsc_elem, rsc_elem.namespaces[rsc_elem.prefix])
            if hot_version == '2015-04-30':
                rsc_dict = Korenv2SliverType.check_is_hot(s_type, rsc_dict)
            else:
                logger.error("Not support the HOT version: %s" % hot_version)
            tmp[rsc_name] = { 'type' : s_type,
                              'properties' : rsc_dict }
            resources.update(tmp)
        return resources

    @staticmethod    
    def get_sliver_elements(rspec_nodes, OSNodeClass, fields=None):
        if len(rspec_nodes) == 0: 
            return None
        ret_list = []
        if fields == None: fields = OSNodeClass.fields
        try:
            for rspec_node in rspec_nodes:
                os_node = OSNodeClass(fields)
                for tag, value in fields.items() : 
                    os_node[tag]=None
                    if isinstance(value, type):
                        #1. openstack resource type
                        os_node[tag] = Korenv2SliverType.get_os_element(
                                            rspec_node.xpath("./openstack:%s"%tag), 
                                            value, fields=None)
                    elif isinstance(value, types.DictType):
                        if value['class']:
                            #2. form of list of element [{...}, ...]
                            os_node[tag]= Korenv2SliverType.get_os_element(
                                                rspec_node.xpath("./openstack:%s"%tag),
                                                value['class'], fields=value['fields'])
                        else: 
                            #3. form of single element {...}
                            dummy_node = Korenv2SliverType.get_os_element(
                                               rspec_node.xpath("./openstack:%s"%tag),
                                               OSResource, fields=value['fields'])
                            if dummy_node: os_node[tag]=dummy_node[0]
                    elif isinstance(value, types.StringType):
                        if value == 'get_resource':
                            #4. hot function type (value=='get_resource', ...)
                            if tag in rspec_node.attrib :
                                if is_uuid(rspec_node.attrib[tag]):
                                    os_node[tag]=rspec_node.attrib[tag]
                                else:
                                    os_node[tag]={value:rspec_node.attrib[tag]}
                        elif value == 'simple_list':
                            #5. simple list type [value, ... 
                            dummy_nodes = Korenv2SliverType.get_os_element(
                                               rspec_node.xpath("./openstack:%s"%tag),
                                               OSResource, fields={'value':None})
                            if dummy_nodes: 
                                os_node[tag] = [dummy_node['value'] for dummy_node in dummy_nodes]
                    else: # 6. xml attribute / simple str, int, bool
                        if tag in rspec_node.attrib: os_node[tag]=rspec_node.attrib[tag]
                ret_list.append(os_node)
        except Exception, e:
            logger.warn("[EXCEPT VALUE] %s,  tag: %s, value: %s in get_os_element" % (e, str(tag), str(value)))        
            
        return ret_list
