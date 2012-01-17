import types
# for get_key_from_incoming_ip
import tempfile
import os
import commands

from sfa.util.faults import RecordNotFound, AccountNotEnabled, PermissionError, MissingAuthority, \
    UnknownSfaType, ExistingRecord, NonExistingRecord
from sfa.util.sfatime import utcparse, datetime_to_epoch
from sfa.util.prefixTree import prefixTree
from sfa.util.xrn import Xrn, get_authority, hrn_to_urn, urn_to_hrn
from sfa.util.plxrn import hrn_to_pl_login_base
from sfa.util.version import version_core
from sfa.util.sfalogging import logger

from sfa.trust.gid import GID 
from sfa.trust.credential import Credential
from sfa.trust.certificate import Certificate, Keypair, convert_public_key
from sfa.trust.gid import create_uuid

from sfa.storage.persistentobjs import RegRecord
from sfa.storage.alchemy import dbsession

class RegistryManager:

    def __init__ (self, config): pass

    # The GENI GetVersion call
    def GetVersion(self, api, options):
        peers = dict ( [ (hrn,interface.get_url()) for (hrn,interface) in api.registries.iteritems() 
                       if hrn != api.hrn])
        xrn=Xrn(api.hrn)
        return version_core({'interface':'registry',
                             'sfa': 2,
                             'geni_api': 2,
                             'hrn':xrn.get_hrn(),
                             'urn':xrn.get_urn(),
                             'peers':peers})
    
    def GetCredential(self, api, xrn, type, is_self=False):
        # convert xrn to hrn     
        if type:
            hrn = urn_to_hrn(xrn)[0]
        else:
            hrn, type = urn_to_hrn(xrn)
            
        # Is this a root or sub authority
        auth_hrn = api.auth.get_authority(hrn)
        if not auth_hrn or hrn == api.config.SFA_INTERFACE_HRN:
            auth_hrn = hrn
        auth_info = api.auth.get_auth_info(auth_hrn)
        # get record info
        record=dbsession.query(RegRecord).filter_by(type=type,hrn=hrn).first()
        if not record:
            raise RecordNotFound(hrn)
    
        # verify_cancreate_credential requires that the member lists
        # (researchers, pis, etc) be filled in
        logger.debug("get credential before augment dict, keys=%s"%record.__dict__.keys())
        self.driver.augment_records_with_testbed_info (record.__dict__)
        logger.debug("get credential after augment dict, keys=%s"%record.__dict__.keys())
        if not self.driver.is_enabled (record.__dict__):
              raise AccountNotEnabled(": PlanetLab account %s is not enabled. Please contact your site PI" %(record.email))
    
        # get the callers gid
        # if this is a self cred the record's gid is the caller's gid
        if is_self:
            caller_hrn = hrn
            caller_gid = record.get_gid_object()
        else:
            caller_gid = api.auth.client_cred.get_gid_caller() 
            caller_hrn = caller_gid.get_hrn()
        
        object_hrn = record.get_gid_object().get_hrn()
        rights = api.auth.determine_user_rights(caller_hrn, record.__dict__)
        # make sure caller has rights to this object
        if rights.is_empty():
            raise PermissionError(caller_hrn + " has no rights to " + record.hrn)
    
        object_gid = GID(string=record.gid)
        new_cred = Credential(subject = object_gid.get_subject())
        new_cred.set_gid_caller(caller_gid)
        new_cred.set_gid_object(object_gid)
        new_cred.set_issuer_keys(auth_info.get_privkey_filename(), auth_info.get_gid_filename())
        #new_cred.set_pubkey(object_gid.get_pubkey())
        new_cred.set_privileges(rights)
        new_cred.get_privileges().delegate_all_privileges(True)
        if hasattr(record,'expires'):
            date = utcparse(record.expires)
            expires = datetime_to_epoch(date)
            new_cred.set_expiration(int(expires))
        auth_kind = "authority,ma,sa"
        # Parent not necessary, verify with certs
        #new_cred.set_parent(api.auth.hierarchy.get_auth_cred(auth_hrn, kind=auth_kind))
        new_cred.encode()
        new_cred.sign()
    
        return new_cred.save_to_string(save_parents=True)
    
    
    def Resolve(self, api, xrns, intype=None, full=True):
    
        if not isinstance(xrns, types.ListType):
            xrns = [xrns]
            # try to infer type if not set and we get a single input
            if not intype:
                intype = Xrn(xrns).get_type()
        hrns = [urn_to_hrn(xrn)[0] for xrn in xrns] 

        # load all known registry names into a prefix tree and attempt to find
        # the longest matching prefix
        # create a dict where key is a registry hrn and its value is a list
        # of hrns at that registry (determined by the known prefix tree).  
        xrn_dict = {}
        registries = api.registries
        tree = prefixTree()
        registry_hrns = registries.keys()
        tree.load(registry_hrns)
        for xrn in xrns:
            registry_hrn = tree.best_match(urn_to_hrn(xrn)[0])
            if registry_hrn not in xrn_dict:
                xrn_dict[registry_hrn] = []
            xrn_dict[registry_hrn].append(xrn)
            
        records = [] 
        for registry_hrn in xrn_dict:
            # skip the hrn without a registry hrn
            # XX should we let the user know the authority is unknown?       
            if not registry_hrn:
                continue
    
            # if the best match (longest matching hrn) is not the local registry,
            # forward the request
            xrns = xrn_dict[registry_hrn]
            if registry_hrn != api.hrn:
                credential = api.getCredential()
                interface = api.registries[registry_hrn]
                server_proxy = api.server_proxy(interface, credential)
                peer_records = server_proxy.Resolve(xrns, credential,intype)
                # pass foreign records as-is
                records.extend(peer_records)
    
        # try resolving the remaining unfound records at the local registry
        local_hrns = list ( set(hrns).difference([record['hrn'] for record in records]) )
        # 
        local_records = dbsession.query(RegRecord).filter(RegRecord.hrn.in_(local_hrns))
        if intype:
            local_records = local_records.filter_by(type=intype)
        local_records=local_records.all()
        local_dicts = [ record.__dict__ for record in local_records ]
        
        if full:
            # in full mode we get as much info as we can, which involves contacting the 
            # testbed for getting implementation details about the record
            for record in local_dicts: logger.info("resolve augment %s"%record)
            self.driver.augment_records_with_testbed_info(local_dicts)
#            # also we fill the 'url' field for known authorities
#            # used to be in the driver code, sounds like a poorman thing though
            def solve_neighbour_url (record):
                if not record.type.startswith('authority'): return 
                hrn=record.hrn
                for neighbour_dict in [ api.aggregates, api.registries ]:
                    if hrn in neighbour_dict:
                        record.url=neighbour_dict[hrn].get_url()
                        return 
            for record in local_records: solve_neighbour_url (record)
        
        # convert local record objects to dicts for xmlrpc
        # xxx somehow here calling dict(record) issues a weird error
        # however record.todict() seems to work fine
#        records.extend( [ dict(record) for record in local_records ] )
        records.extend( [ record.todict() for record in local_records ] )    
        if not records:
            raise RecordNotFound(str(hrns))
    
        return records
    
    def List (self, api, xrn, origin_hrn=None):
        hrn, type = urn_to_hrn(xrn)
        # load all know registry names into a prefix tree and attempt to find
        # the longest matching prefix
        registries = api.registries
        registry_hrns = registries.keys()
        tree = prefixTree()
        tree.load(registry_hrns)
        registry_hrn = tree.best_match(hrn)
       
        #if there was no match then this record belongs to an unknow registry
        if not registry_hrn:
            raise MissingAuthority(xrn)
        # if the best match (longest matching hrn) is not the local registry,
        # forward the request
        record_dicts = []    
        if registry_hrn != api.hrn:
            credential = api.getCredential()
            interface = api.registries[registry_hrn]
            server_proxy = api.server_proxy(interface, credential)
            record_list = server_proxy.List(xrn, credential)
            # pass foreign records as-is
            record_dicts = record_list
        
        # if we still have not found the record yet, try the local registry
        if not record_dicts:
            if not api.auth.hierarchy.auth_exists(hrn):
                raise MissingAuthority(hrn)
            records = dbsession.query(RegRecord).filter_by(authority=hrn)
            record_dicts=[ record.todict() for record in records ]
    
        return record_dicts
    
    
    def CreateGid(self, api, xrn, cert):
        # get the authority
        authority = Xrn(xrn=xrn).get_authority_hrn()
        auth_info = api.auth.get_auth_info(authority)
        if not cert:
            pkey = Keypair(create=True)
        else:
            certificate = Certificate(string=cert)
            pkey = certificate.get_pubkey()    
        gid = api.auth.hierarchy.create_gid(xrn, create_uuid(), pkey) 
        return gid.save_to_string(save_parents=True)
    
    ####################
    # utility for handling relationships among the SFA objects 
    # given that the SFA db does not handle this sort of relationsships
    # it will rely on side-effects in the testbed to keep this persistent
    
    # subject_record describes the subject of the relationships
    # ref_record contains the target values for the various relationships we need to manage
    # (to begin with, this is just the slice x person relationship)
    def update_relations (self, subject_obj, ref_obj):
        type=subject_obj.type
        if type=='slice':
            self.update_relation(subject_obj, 'researcher', ref_obj.researcher, 'user')
        
    # field_key is the name of one field in the record, typically 'researcher' for a 'slice' record
    # hrns is the list of hrns that should be linked to the subject from now on
    # target_type would be e.g. 'user' in the 'slice' x 'researcher' example
    def update_relation (self, record_obj, field_key, hrns, target_type):
        # locate the linked objects in our db
        subject_type=record_obj.type
        subject_id=record_obj.pointer
        # get the 'pointer' field of all matching records
        link_id_tuples = dbsession.query(RegRecord.pointer).filter_by(type=target_type).filter(RegRecord.hrn.in_(hrns)).all()
        # sqlalchemy returns named tuples for columns
        link_ids = [ tuple.pointer for tuple in link_id_tuples ]
        self.driver.update_relation (subject_type, target_type, subject_id, link_ids)

    def Register(self, api, record_dict):
    
        hrn, type = record_dict['hrn'], record_dict['type']
        urn = hrn_to_urn(hrn,type)
        # validate the type
        if type not in ['authority', 'slice', 'node', 'user']:
            raise UnknownSfaType(type) 
        
        # check if record_dict already exists
        existing_records = dbsession.query(RegRecord).filter_by(type=type,hrn=hrn).all()
        if existing_records:
            raise ExistingRecord(hrn)
           
        assert ('type' in record_dict)
        record = RegRecord("undefined")
        record.set_from_dict(record_dict)
        record.just_created()
        record.authority = get_authority(record.hrn)
        auth_info = api.auth.get_auth_info(record.authority)
        pub_key = None
        # make sure record has a gid
        if not record.gid:
            uuid = create_uuid()
            pkey = Keypair(create=True)
            if getattr(record,'keys',None):
                pub_key=record.keys
                # use only first key in record
                if isinstance(record.keys, types.ListType):
                    pub_key = record.keys[0]
                pkey = convert_public_key(pub_key)
    
            gid_object = api.auth.hierarchy.create_gid(urn, uuid, pkey)
            gid = gid_object.save_to_string(save_parents=True)
            record.gid = gid
    
        if type in ["authority"]:
            # update the tree
            if not api.auth.hierarchy.auth_exists(hrn):
                api.auth.hierarchy.create_auth(hrn_to_urn(hrn,'authority'))
    
            # get the GID from the newly created authority
            gid = auth_info.get_gid_object()
            record.gid=gid.save_to_string(save_parents=True)

        # update testbed-specific data if needed
        pointer = self.driver.register (record.__dict__, hrn, pub_key)

        record.pointer=pointer
        dbsession.add(record)
        dbsession.commit()
    
        # update membership for researchers, pis, owners, operators
        self.update_relations (record, record)
        
        return record.get_gid_object().save_to_string(save_parents=True)
    
    def Update(self, api, record_dict):
        assert ('type' in record_dict)
        new_record=RegRecord(type="unknown")
        new_record.set_from_dict(record_dict)
        type = new_record.type
        hrn = new_record.hrn
        
        # make sure the record exists
        record = dbsession.query(RegRecord).filter_by(type=type,hrn=hrn).first()
        if not record:
            raise RecordNotFound(hrn)
        record.just_updated()
    
        # validate the type
        # xxx might be simpler to just try to commit as this is a constraint in the db
        if type not in ['authority', 'slice', 'node', 'user']:
            raise UnknownSfaType(type) 

        # Use the pointer from the existing record, not the one that the user
        # gave us. This prevents the user from inserting a forged pointer
        pointer = record.pointer
    
        # is the a change in keys ?
        new_key=None
        if type=='user':
            if getattr(new_key,'keys',None):
                new_key=new_record.keys
                if isinstance (new_key,types.ListType):
                    new_key=new_key[0]

        # update the PLC information that was specified with the record
        if not self.driver.update (record.__dict__, new_record.__dict__, hrn, new_key):
            logger.warning("driver.update failed")
    
        # take new_key into account
        if new_key:
            # update the openssl key and gid
            pkey = convert_public_key(new_key)
            uuid = create_uuid()
            urn = hrn_to_urn(hrn,type)
            gid_object = api.auth.hierarchy.create_gid(urn, uuid, pkey)
            gid = gid_object.save_to_string(save_parents=True)
            record.gid = gid
            dsession.commit()
        
        # update membership for researchers, pis, owners, operators
        self.update_relations (record, new_record)
        
        return 1 
    
    # expecting an Xrn instance
    def Remove(self, api, xrn, origin_hrn=None):
        hrn=xrn.get_hrn()
        type=xrn.get_type()
        request=dbsession.query(RegRecord).filter_by(hrn=hrn)
        if type and type not in ['all', '*']:
            request=request.filter_by(type=type)
    
        record = request.first()
        if not record:
            msg="Could not find hrn %s"%hrn
            if type: msg += " type=%s"%type
            raise RecordNotFound(msg)

        type = record.type
        credential = api.getCredential()
        registries = api.registries
    
        # Try to remove the object from the PLCDB of federated agg.
        # This is attempted before removing the object from the local agg's PLCDB and sfa table
        if hrn.startswith(api.hrn) and type in ['user', 'slice', 'authority']:
            for registry in registries:
                if registry not in [api.hrn]:
                    try:
                        result=registries[registry].remove_peer_object(credential, record, origin_hrn)
                    except:
                        pass

        # call testbed callback first
        # IIUC this is done on the local testbed TOO because of the refreshpeer link
        if not self.driver.remove(record.__dict__):
            logger.warning("driver.remove failed")

        # delete from sfa db
        del record
        dbsession.commit()
    
        return 1

    # This is a PLC-specific thing, won't work with other platforms
    def get_key_from_incoming_ip (self, api):
        # verify that the callers's ip address exist in the db and is an interface
        # for a node in the db
        (ip, port) = api.remote_addr
        interfaces = self.driver.shell.GetInterfaces({'ip': ip}, ['node_id'])
        if not interfaces:
            raise NonExistingRecord("no such ip %(ip)s" % locals())
        nodes = self.driver.shell.GetNodes([interfaces[0]['node_id']], ['node_id', 'hostname'])
        if not nodes:
            raise NonExistingRecord("no such node using ip %(ip)s" % locals())
        node = nodes[0]
       
        # look up the sfa record
        record=dbsession.query(RegRecord).filter_by(type='node',pointer=node['node_id']).first()
        if not record:
            raise RecordNotFound("node with pointer %s"%node['node_id'])
        
        # generate a new keypair and gid
        uuid = create_uuid()
        pkey = Keypair(create=True)
        urn = hrn_to_urn(record.hrn, record.type)
        gid_object = api.auth.hierarchy.create_gid(urn, uuid, pkey)
        gid = gid_object.save_to_string(save_parents=True)
        record.gid = gid

        # update the record
        dbsession.commit()
  
        # attempt the scp the key
        # and gid onto the node
        # this will only work for planetlab based components
        (kfd, key_filename) = tempfile.mkstemp() 
        (gfd, gid_filename) = tempfile.mkstemp() 
        pkey.save_to_file(key_filename)
        gid_object.save_to_file(gid_filename, save_parents=True)
        host = node['hostname']
        key_dest="/etc/sfa/node.key"
        gid_dest="/etc/sfa/node.gid" 
        scp = "/usr/bin/scp" 
        #identity = "/etc/planetlab/root_ssh_key.rsa"
        identity = "/etc/sfa/root_ssh_key"
        scp_options=" -i %(identity)s " % locals()
        scp_options+="-o StrictHostKeyChecking=no " % locals()
        scp_key_command="%(scp)s %(scp_options)s %(key_filename)s root@%(host)s:%(key_dest)s" %\
                         locals()
        scp_gid_command="%(scp)s %(scp_options)s %(gid_filename)s root@%(host)s:%(gid_dest)s" %\
                         locals()    

        all_commands = [scp_key_command, scp_gid_command]
        
        for command in all_commands:
            (status, output) = commands.getstatusoutput(command)
            if status:
                raise Exception, output

        for filename in [key_filename, gid_filename]:
            os.unlink(filename)

        return 1 
