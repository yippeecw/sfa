import os

from sfa.util.config import Config
from sfa.util.xrn import Xrn, get_leaf, get_authority, hrn_to_urn
from sfa.trust.gid import create_uuid    
from sfa.trust.certificate import convert_public_key, Keypair
# using global alchemy.session() here is fine 
# as importer is on standalone one-shot process
from sfa.storage.alchemy import global_dbsession
from sfa.storage.model import RegRecord, RegAuthority, RegUser, RegSlice
from sfa.openstack.osxrn import OSXrn
from sfa.openstack.shell import Shell    

def load_keys(filename):
    keys = {}
    tmp_dict = {}
    try:
        execfile(filename, tmp_dict)
        if 'keys' in tmp_dict:
            keys = tmp_dict['keys']
        return keys
    except:
        return keys

def save_keys(filename, keys):
    f = open(filename, 'w')
    f.write("keys = %s" % str(keys))
    f.close()

class OpenstackImporter:

    def __init__ (self, auth_hierarchy, logger):
        self.auth_hierarchy = auth_hierarchy
        self.logger=logger
        self.config = Config()
        self.interface_hrn = self.config.SFA_INTERFACE_HRN
        self.root_auth = self.config.SFA_REGISTRY_ROOT_AUTH
        self.shell = Shell(self.config)

    def add_options (self, parser):
        self.logger.debug ("OpenstackImporter: no options yet")
        pass

    def import_users(self, existing_hrns, existing_records):
        # Get all users
        users = self.shell.auth_manager.users.list()
        users_dict = {}
        keys_filename = self.config.config_path + os.sep + 'person_keys.py'
        old_user_keys = load_keys(keys_filename)
        user_keys = {}
        for user in users:
            auth_hrn = self.config.SFA_INTERFACE_HRN
            try:
                user_tenantId = user.tenantId
                user_email = user.email
            except AttributeError, e:
                user_tenantId = None
                user_email = None

            if user_tenantId is not None:
                tenant = self.shell.auth_manager.tenants.find(id=user_tenantId)
                auth_hrn = OSXrn(name=tenant.name, auth=self.config.SFA_INTERFACE_HRN, type='authority').get_hrn()
            hrn = OSXrn(name=user.name, auth=auth_hrn, type='user').get_hrn()
            users_dict[hrn] = user
            old_keys = old_user_keys.get(hrn, [])
            keyname = OSXrn(xrn=hrn, type='user').get_slicename()
            keys = [k.public_key for k in self.shell.compute_manager.keypairs.findall(name=keyname)]
            user_keys[hrn] = keys
            update_record = False
            if old_keys != keys:
                update_record = True
            if hrn not in existing_hrns or \
                   (hrn, 'user') not in existing_records or update_record:
                urn = OSXrn(xrn=hrn, type='user').get_urn()
                if keys:
                    try:
                        pkey = convert_public_key(keys[0])
                    except:
                        self.logger.log_exc('unable to convert public key for %s' % hrn)
                        pkey = Keypair(create=True)
                else:
                    self.logger.warn("OpenstackImporter: person %s does not have a PL public key"%hrn)
                    pkey = Keypair(create=True)
                user_gid = self.auth_hierarchy.create_gid(urn, create_uuid(), pkey, email=user_email)
                user_record = RegUser(type='user', 
                                      hrn=hrn, 
                                      gid=user_gid, 
                                      authority=get_authority(hrn))
                global_dbsession.add(user_record)
                global_dbsession.commit()
                self.logger.info("OpenstackImporter: imported person %s" % user_record)
        return users_dict, user_keys

    def import_tenants(self, existing_hrns, existing_records):
        # Get all tenants
        # A tenant can represent an organizational group (site) or a
        # slice. If a tenant's authorty/parent matches the root authority it is
        # considered a group/site. All other tenants are considered slices.
        tenants = self.shell.auth_manager.tenants.list()
        tenants_dict = {}
        for tenant in tenants:
            hrn = self.config.SFA_INTERFACE_HRN + '.' + tenant.name
            tenants_dict[hrn] = tenant
            authority_hrn = OSXrn(xrn=hrn, type='authority').get_authority_hrn()
        
            if hrn in existing_hrns:
                continue

            if authority_hrn == self.config.SFA_INTERFACE_HRN:
                # import group/site
                urn = OSXrn(xrn=hrn, type='authority').get_urn()
                if not self.auth_hierarchy.auth_exists(urn):
                    self.auth_hierarchy.create_auth(urn)
                auth_info = self.auth_hierarchy.get_auth_info(urn)
                gid = auth_info.get_gid_object()
                auth_record = RegAuthority(type='authority',
                                           hrn=hrn,
                                           gid=gid,
                                           authority=get_authority(hrn))
                global_dbsession.add(auth_record)
                global_dbsession.commit()
                self.logger.info("OpenstackImporter: imported authority: %s" % auth_record)

            else:
                urn = OSXrn(xrn=hrn, type='slice').get_urn()
                pkey = Keypair(create=True)
                gid = self.auth_hierarchy.create_gid(urn, create_uuid(), pkey)
                slice_record = RegSlice(type='slice',
                                        hrn=hrn,
                                        gid=gid,
                                        authority=get_authority(hrn))
                global_dbsession.add(slice_record)
                global_dbsession.commit()
                self.logger.info("OpenstackImporter: imported slice: %s" % slice_record) 

        return tenants_dict

    def run (self, options):
        # we don't have any options for now
        self.logger.info ("OpenstackImporter.run : to do")

        # added only try and except statement to handle external user's info
        try:
            # create dict of all existing sfa records
            existing_records = {}
            existing_hrns = []
            key_ids = []
            for record in global_dbsession.query(RegRecord):
                existing_records[ (record.hrn, record.type) ] = record
                existing_hrns.append(record.hrn) 

            tenants_dict = self.import_tenants(existing_hrns, existing_records)
            users_dict, user_keys = self.import_users(existing_hrns, existing_records)
      
            # remove stale records    
            system_records = [self.interface_hrn, self.root_auth, self.interface_hrn + '.slicemanager']
            for (record_hrn, type) in existing_records.keys():
                if record_hrn in system_records:
                    continue
        
                record = existing_records[(record_hrn, type)]
                if record.peer_authority:
                    continue

                if type == 'user':
                    if record_hrn in users_dict:
                        continue  
                elif type in['slice', 'authority']:
                    if record_hrn in tenants_dict:
                        continue
                else:
                    continue 
        
                record_object = existing_records[ (record_hrn, type) ]
                self.logger.info("OpenstackImporter: removing %s " % record)
                global_dbsession.delete(record_object)
                global_dbsession.commit()

            # save pub keys
            self.logger.info('OpenstackImporter: saving current pub keys')
            keys_filename = self.config.config_path + os.sep + 'person_keys.py'
            save_keys(keys_filename, user_keys)                
        
        except Exception, e:
            self.logger.error("It's caused by external user/slice : %s" % e)
