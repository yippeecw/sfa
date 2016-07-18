######################################################################################################
# Edited on Jun 20, 2015                                                                             #
# Code modified by Chaima Ghribi.                                                                    #
# The original code is available on github at https://github.com/onelab-eu/sfa/tree/openstack-driver.#
# Modifications are noted as comments in the code itself.                                            #
# @contact: chaima.ghribi@it-sudparis.eu                                                             #
# @organization: Institut Mines-Telecom - Telecom SudParis                                           #
######################################################################################################

import os
import socket
import base64
import string
import random
import time    
from collections import defaultdict
from sfa.util.faults import SliverDoesNotExist
from sfa.util.sfatime import utcparse, datetime_to_string, datetime_to_epoch
from sfa.util.xrn import Xrn, get_leaf, hrn_to_urn
from sfa.util.sfalogging import logger
from sfa.storage.model import SliverAllocation

import json
from sfa.rspecs.rspec import RSpec
from sfa.rspecs.elements.openstackv2 import *
from sfa.rspecs.version_manager import VersionManager
from sfa.rspecs.elements.hardware_type import HardwareType
from sfa.rspecs.elements.sliver import Sliver
from sfa.rspecs.elements.login import Login
from sfa.rspecs.elements.services import ServicesElement
from sfa.rspecs.elements.location import Location

from sfa.client.multiclient import MultiClient
from sfa.openstack.osxrn import OSXrn, hrn_to_os_slicename
from sfa.openstack.security_group import SecurityGroup
from sfa.openstack.osconfig import OSConfig

# for exception
from novaclient import exceptions


def pubkeys_to_user_data(pubkeys):
    user_data = "#!/bin/bash\n\n"
    for pubkey in pubkeys:
        pubkey = pubkey.replace('\n', '')
        user_data += "echo %s >> /root/.ssh/authorized_keys" % pubkey
        user_data += "\n"
        user_data += "echo >> /root/.ssh/authorized_keys"
        user_data += "\n"
    return user_data

class OSAggregate:

    def __init__(self, driver):
        logger.debug("start OS DRIVER")
        self.driver = driver

    def get_availability_zones(self, zones=None):
        # Update inital connection info
        self.driver.init_compute_manager_conn()
        zone_list=[]
        if not zones:
            availability_zones = self.driver.shell.compute_manager.availability_zones.list()
            for zone in availability_zones:
                if (zone.zoneState.get('available') == True) and \
                   (zone.zoneName != 'internal'):
                    zone_list.append(zone.zoneName)
        else:
            availability_zones = self.driver.shell.compute_manager.availability_zones.list()
            for a_zone in availability_zones:
                for i_zone in zones:
                    if a_zone.zoneName == i_zone: 
                        if (a_zone.zoneState.get('available') == True) and \
                           (a_zone.zoneName != 'internal'):
                            zone_list.append(a_zone.zoneName)
        return zone_list

########## ListResources API                  
    def list_resources(self, version=None, options=None):
        if options is None: options={}
        version_manager = VersionManager()
        version = version_manager.get_version(version)
        rspec_version = version_manager._get_version(version.type, version.version, 'ad')
        rspec = RSpec(version=version, user_options=options)
        nodes = self.get_aggregate_nodes()
        rspec.version.add_nodes(nodes=nodes, rspec_content_type='openstack')
        return rspec.toxml()

    def get_aggregate_nodes(self):
        os_rspec_nodes=[]
        os_rspec_node = OSNode()
        xrn = Xrn(self.driver.hrn+'.'+'openstack', type='node')
        os_rspec_node['component_manager_id'] = Xrn(self.driver.hrn, type='authority+am').get_urn()
        os_rspec_node['component_id'] = xrn.urn
        os_rspec_node['heat_template_version'] = "2015-04-30"
        os_rspec_node['name'] = "advertisement"
        #TODO: For Multi OS location
#        site = self.driver.openstackInfo
#        if site['longitude'] and site['latitude']:
#            os_res_type['location'] = Location({'longitude': site['longitude'], 'latitude': site['latitude'], 'country': 'unknown'})
#        os_res_type['tags'] = []

        # Get list of images for OsNovaServer
        available_images=[]
        images = self.driver.shell.compute_manager.images.list()
        for image in images:
            if image.status == 'ACTIVE':
                img = { 'name': str(image.name),
                        'id' : str(image.id),
                        'minDisk' : int(image.minDisk),
                        'minRam' : int(image.minRam)
                }
                available_images.append(img)

        # Get list of flavors for OSNovaServer
        available_flavors=[]
        flavors = self.driver.shell.compute_manager.flavors.list()
        for flavor in flavors:
            if flavor.__getattr__('os-flavor-access:is_public') is True:
                flv = { 'name' : str(flavor.name),
                        'id' : str(flavor.id),
                        'vcpus' : int(flavor.vcpus), 
                        'ram' : int(flavor.ram),
                        'disk' : int(flavor.disk)
                }
                available_flavors.append(flv)

        # Get list of available zones for OSNovaServer
        #TODO: To classify where is allocated with a zone
        available_zones=[]
        zones = self.get_availability_zones()
        for zone in zones:
            zn = {'zone' : str(zone) }
            available_zones.append(zn)

        # Get list of available security groups for OSNovaServer
        available_security_groups=[]
        groups = self.driver.shell.compute_manager.security_groups.list()
        for group in groups:
            group_rules=[]
            for rule in group.rules:
                rl = { 'to_port': str(rule['to_port']),
                       'from_port': str(rule['from_port']),
                       'ip_protocol': str(rule['ip_protocol']),
                       'ip_range': str(rule['ip_range'])
                }
                group_rules.append(rl)
            grp = { 'group' : str(group.name),
                    'description' : str(group.description),
                    'rules' : group_rules
            }
            available_security_groups.append(grp)

        osnovaserver = { 'images' : available_images,
                         'flavors': available_flavors,
                         'availability_zones' : available_zones,
                         'security_groups' : available_security_groups
        }
        os_rspec_node['slivers'] = [{ 'OSNovaServer' : osnovaserver }]
        os_rspec_nodes.append(os_rspec_node)
        return os_rspec_nodes

    def describe(self, urns, version=None, options=None):
        if options is None: options={}
        version_manager = VersionManager()
        version = version_manager.get_version(version)
        rspec_version = version_manager._get_version(version.type, version.version, 'manifest')
        rspec = RSpec(version=rspec_version, user_options=options)

        # Update connection for the current user
        xrn = Xrn(urns[0], type='slice')
        if options.get('actual_caller_hrn'):
            if options['actual_caller_hrn'] is (xrn.get_authority_hrn() + '.' + xrn.leaf.split('-')[0]):
                user_name = options['actual_caller_hrn']
            else:
                user_name = xrn.get_authority_hrn() + '.' + xrn.leaf.split('-')[0]
        else:
             user_name = xrn.get_authority_hrn() + '.' + xrn.leaf.split('-')[0]
#cwkim: replace to option processing [TODO]
#        if options['actual_caller_hrn'] is None:
#            user_name = xrn.get_authority_hrn() + '.' + xrn.leaf.split('-')[0]
#        else:
#            user_name = options['actual_caller_hrn']
        tenant_name = OSXrn(xrn=urns[0], type='slice').get_hrn()
        self.driver.shell.orchest_manager.connect(username=user_name, tenant=tenant_name, password=user_name)
        # Get stacks(=instances) from the Openstack Heat
        stacks = self.get_instances(xrn)
       
        # Add slivers from stacks(=nodes)
#        geni_slivers=[]
        rspec.xml.set('expires',datetime_to_string(utcparse(time.time())))
        rspec_nodes=[]
        for stack in stacks:
            rspec_nodes.append(self.instance_to_rspec_node(stack))
#cwkim: geni_sliver =/= stack, stack is node or instance concept
#            geni_sliver = self.instance_to_geni_sliver(instance)
#            geni_slivers.append(geni_sliver)
        rspec.version.add_nodes(rspec_nodes)
        result = { 'geni_urn': xrn.get_urn(),
                   'geni_rspec': rspec.toxml()
#                   'geni_slivers': geni_slivers 
                 }
        return result

    def get_instances(self, xrn):
        # parse slice names and sliver ids
        slice_names=[]
        instances=[]
        if xrn.type == 'slice':
            slice_names.append(xrn.get_hrn())
        else:
            print "[WARN] We don't know the xrn[%s]" % xrn.type
            logger.warn("[WARN] We don't know the xrn[%s], Check it!" % xrn.type)
            
        # look up instances using stacks of Heat
        try:
            for slice_name in slice_names:
                stacks = self.driver.shell.orchest_manager.stacks.list()
                instances.extend(stacks)
        except(exceptions.Unauthorized):
            print "[WARN] The stack(s) in Openstack is/are not permitted."
            logger.warn("The stack(s) in Openstack is/are not permitted.")
            return []
        return list( set(instances) )

    def instance_to_rspec_node(self, instance):
        rspec_node = OSNode()
        # determine node urn
        node_xrn = instance.description.get('component_id')
        if not node_xrn:
            node_xrn = OSXrn(self.driver.hrn+'.'+'openstack', type='node')
        else:
            node_xrn = OSXrn(xrn=node_xrn, type='node')
        rspec_node['component_id'] = node_xrn.urn
        if not instance.description.get('component_manager_id'):
            rspec_node['component_manager_id'] = Xrn(self.driver.hrn, type='authority+am').get_urn()
        else:
            rspec_node['component_manager_id'] = instance.description.get('component_manager_id')
        rspec_node['name'] = instance.stack_name
        rspec_node['node_id'] = OSXrn(name=(self.driver.api.hrn+'.'+ instance.stack_name), \
                                      id=instance.id, type='node+openstack').get_urn()
        rspec_node['status'] = instance.status
#        rspec_node['location']
        template = self.driver.shell.orchest_manager.stacks.template(instance.id)
        rspec_node['heat_template_version'] = template.get('heat_template_version')
        rspec_node['tags'] = [ instance.stack_status_reason ]
        rspec_node['slivers'] = [ template ]
        return rspec_node

    def instance_to_geni_sliver(self, instance):
        sliver_id = OSXrn(name=(self.driver.api.hrn+'.'+ instance.stack_name), id=instance.id, \
                          type='node+openstack').get_urn()
        logger.info("sliver_id: %s in instance_to_geni_sliver" % sliver_id)

        constraint = SliverAllocation.sliver_id.in_([sliver_id])
        sliver_allocations = list(self.driver.api.dbsession().query(SliverAllocation).filter(constraint))
        if sliver_allocations:
            sliver_allocation_status = sliver_allocations[0].allocation_state
        else:
            sliver_allocation_status = None

        error = 'None'
        op_status = 'geni_unknown'
        if sliver_allocation_status:
            if sliver_allocation_status == 'geni_allocated':
                op_status = 'geni_pending_allocation'
            elif sliver_allocation_status == 'geni_provisioned':
                state = instance.status.lower()
                if state == 'active':
                    op_status = 'geni_ready'
                elif state == 'build':
                    op_status = 'geni_not_ready'
                elif state == 'error':
                    op_status = 'geni_failed'
                    error = "Retry to provisioning them!"
                else:
                    op_status = 'geni_unknown'
            elif sliver_allocation_status == 'geni_unallocated':
                op_status = 'geni_not_ready'
        else:
            sliver_allocation_status = 'geni_unknown'

        geni_sliver = { 'geni_sliver_urn': sliver_id, 
                        'geni_expires': None,
                        'geni_allocation_status': sliver_allocation_status,
                        'geni_operational_status': op_status,
                        'geni_error': error,
                        'os_sliver_created_time': instance.creation_time
                      }
        return geni_sliver

    def create_tenant(self, tenant_name, description=None):
        tenants = self.driver.shell.auth_manager.tenants.findall(name=tenant_name)
        if not tenants:
            tenant = self.driver.shell.auth_manager.tenants.create(tenant_name, description)
        else:
            tenant = tenants[0]
        return tenant


    def create_user(self, user_name, password, tenant_id, email=None, enabled=True):
        if password is None:
            logger.warning("If you want to make a user, you should include your password!!")
            raise ValueError('You should include your password!!')

        users = self.driver.shell.auth_manager.users.findall()
        for user in users:
            if user_name == user.name:
                user_info = user
                logger.info("The user name[%s] already exists." % user_name)
                break
        else:
            user_info = self.driver.shell.auth_manager.users.create(user_name, password, \
                                                             email, tenant_id, enabled)
        return user_info
    
    def create_security_group(self, slicename, fw_rules=None):
        if fw_rules is None: fw_rules=[]
        # use default group by default
        group_name = 'default' 
        if isinstance(fw_rules, list) and fw_rules:
            # Each sliver get's its own security group.
            # Keep security group names unique by appending some random
            # characters on end.
            random_name = "".join([random.choice(string.letters+string.digits)
                                           for i in xrange(6)])
            group_name = slicename + random_name 
            security_group = SecurityGroup(self.driver)
            security_group.create_security_group(group_name)
            for rule in fw_rules:
                security_group.add_rule_to_group(group_name, 
                                             protocol = rule.get('protocol'), 
                                             cidr_ip = rule.get('cidr_ip'), 
                                             port_range = rule.get('port_range'), 
                                             icmp_type_code = rule.get('icmp_type_code'))
            # Open ICMP by default
            security_group.add_rule_to_group(group_name,
                                             protocol = "icmp",
                                             cidr_ip = "0.0.0.0/0",
                                             icmp_type_code = "-1:-1")
        return group_name

    def add_rule_to_security_group(self, group_name, **kwds):
        security_group = SecurityGroup(self.driver)
        security_group.add_rule_to_group(group_name=group_name, 
                                         protocol=kwds.get('protocol'), 
                                         cidr_ip =kwds.get('cidr_ip'), 
                                         icmp_type_code = kwds.get('icmp_type_code'))

    def check_floatingip(self, instances, value):
        if not instances: return None
        servers=[]
        try:
            # True: Find servers which not assigned floating IPs
            if value is True:
                for instance in instances:
                    for addrs in instance.addresses.values():
                        for addr in addrs:
                            if addr.get('OS-EXT-IPS:type') == 'floating':
                                break
                        else:
                            servers.append(instance)
            # False: Find servers which assigned floating IPs
            else:
                for instance in instances:
                    for addrs in instance.addresses.values():
                        for addr in addrs:
                            if addr.get('OS-EXT-IPS:type') == 'floating':
                                servers.append(instance)
        except AttributeError, e:
            servers = instances
        return servers

    def create_floatingip(self, tenant_name, instances):
        if not instances: return None
        config = OSConfig()
        # Information of public network(external network) from configuration file
        extnet_name = config.get('network', 'external_network_name')
        tenant = self.driver.shell.auth_manager.tenants.find(name=tenant_name)
        networks = self.driver.shell.network_manager.list_networks().get('networks')
        for network in networks:
            if (network.get('name') == extnet_name) or \
               (network.get('name') == 'public') or (network.get('name') == 'ext-net'):
                pub_net_id = network.get('id')
                break
        else:
            logger.warning("We shoud need the public network ID for floating IPs!")
            raise ValueError("The public network ID was not found!")
        ports = self.driver.shell.network_manager.list_ports().get('ports')
        for port in ports:
            device_id = port.get('device_id')
            for instance in instances:
                if device_id == instance.id:
                    body = { "floatingip":
                             { "floating_network_id": pub_net_id,
                               "tenant_id": tenant.id,
                               "port_id": port.get('id') } } 
                    self.driver.shell.network_manager.create_floatingip(body=body)

    def delete_floatingip(self, instances):
        if not instances: return None
        floating_ips = self.driver.shell.network_manager.list_floatingips().get('floatingips')
        for ip in floating_ips:
            ip_tenant_id = ip.get('tenant_id')
            for instance in instances:
                if ip_tenant_id == instance.tenant_id:
                    self.driver.shell.network_manager.delete_floatingip(floatingip=ip.get('id'))

    def check_server_status(self, server):
        while (server.status.lower() == 'build'):
            time.sleep(0.5)
            server = self.driver.shell.compute_manager.servers.findall(id=server.id)[0]
        return server

    def check_stack_status(self, stack):
        while (stack.stack_status == 'CREATE_IN_PROGRESS'):
            time.sleep(0.5)
            stack = self.driver.shell.orchest_manager.stacks.get(stack.id)
        if stack.stack_status != 'CREATE_COMPLETE':
            self.driver.shell.orchest_manager.stacks.delete(stack.id)
            stack = None
        return stack

    def run_instances(self, tenant_name, user_name, rspec, key_name, pubkeys):
        slivers=[]
        # It'll use Openstack admin info. as authoirty
        zones = self.get_availability_zones()
        self.driver.shell.orchest_manager.connect(username=user_name, tenant=tenant_name, password=user_name)
        tenant = self.driver.shell.auth_manager.tenants.find(name=tenant_name)
        logger.info( "Checking if the created tenant[%s] or not ..." % tenant_name )
           
        version_manager = VersionManager()
        version_dict = {'type':'KOREN', 'version':'2', 'content_type':'request'}
        version = version_manager.get_version(version_dict)
        rspec_version = version_manager._get_version(version.type, version.version, 'request')
        rspec = RSpec(rspec, version=rspec_version)

        if len(pubkeys):
            files = None
        else:
            authorized_keys = "\n".join(pubkeys)
            files = {'/root/.ssh/authorized_keys': authorized_keys}
        for node in rspec.version.get_nodes_with_slivers():
            instances = [ node.get('slivers') ]
            for instance in instances:
                 stack = self.driver.shell.orchest_manager.stacks.create( \
                              stack_name=node.get('name'), template=json.dumps(instance))
                 sliver = self.driver.shell.orchest_manager.stacks.get(stack['stack']['id'])
                 sliver = self.check_stack_status(sliver)
                 if sliver: slivers.append(sliver)
                 logger.info("Created Openstack stack [%s]" % sliver.stack_name)
        return slivers

    def delete_instance(self, instance):
    
        def _delete_security_group(instance):
            if hasattr(instance, 'metadata'):
                if hasattr(instance.metadata, 'security_groups'):
                    security_group = instance.metadata.get('security_groups', '')
                    if security_group:
                        manager = SecurityGroup(self.driver)
                        timeout = 10.0 # wait a maximum of 10 seconds before forcing the security group delete
                        start_time = time.time()
                        instance_deleted = False
                        while instance_deleted == False and (time.time() - start_time) < timeout:
                            tmp_inst = self.driver.shell.orchest_manager.stacks.get(id=instance.id)
                            if not tmp_inst:
                                instance_deleted = True
                            time.sleep(.5)
                        manager.delete_security_group(security_group)

        self.driver.shell.orchest_manager.stacks.delete(instance.id)
        while (self.driver.shell.orchest_manager.stacks.get(instance.id).stack_status != 'DELETE_COMPLETE'):
            time.sleep(0.5)   
        logger.info("[Delete] Stack status : %s " % (self.driver.shell.orchest_manager.stacks.get(instance.id).stack_status))
        
        # deleate the instance's security groups
        multiclient = MultiClient()
        security_group_manager = SecurityGroup(self.driver)
        multiclient.run(_delete_security_group, instance)
        return 1

    def stop_instances(self, instance_name, tenant_name, id=None):
        # Update connection for the current client
        xrn = Xrn(tenant_name)
        user_name = xrn.get_authority_hrn() + '.' + xrn.leaf.split('-')[0]
        self.driver.shell.compute_manager.connect(username=user_name, tenant=tenant_name, password=user_name)

        args = { 'name': instance_name }
        if id:
            args['id'] = id
        instances = self.driver.shell.compute_manager.servers.findall(**args)
        for instance in instances:
            self.driver.shell.compute_manager.servers.pause(instance)
        return 1

    def start_instances(self, instance_name, tenant_name, id=None):
        # Update connection for the current client
        xrn = Xrn(tenant_name)
        user_name = xrn.get_authority_hrn() + '.' + xrn.leaf.split('-')[0]
        self.driver.shell.compute_manager.connect(username=user_name, tenant=tenant_name, password=user_name)

        args = { 'name': instance_name }
        if id:
            args['id'] = id
        instances = self.driver.shell.compute_manager.servers.findall(**args)
        for instance in instances:
            self.driver.shell.compute_manager.servers.resume(instance)
        return 1

    def restart_instances(self, instacne_name, tenant_name, id=None):
        # Update connection for the current client
        xrn = Xrn(tenant_name)
        user_name = xrn.get_authority_hrn() + '.' + xrn.leaf.split('-')[0]
        self.driver.shell.compute_manager.connect(username=user_name, tenant=tenant_name, password=user_name)

        self.stop_instances(instance_name, tenant_name, id)
        self.start_instances(instance_name, tenant_name, id)
        return 1 

    def update_instances(self, project_name):
        pass
