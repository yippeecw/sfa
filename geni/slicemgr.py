import os
import sys
import datetime
import time

from geni.util.geniserver import *
from geni.util.geniclient import *
from geni.util.cert import *
from geni.util.credential import Credential
from geni.util.trustedroot import *
from geni.util.excep import *
from geni.util.misc import *
from geni.util.config import Config
from geni.util.rspec import Rspec
from geni.util.specdict import *
from geni.util.storage import SimpleStorage

class SliceMgr(GeniServer):

    hrn = None
    nodes_ttl = None
    nodes = None
    slices = None
    policy = None
    aggregates = None
    timestamp = None
    threshold = None    
    shell = None
    registry = None
    key_file = None
    cert_file = None
    credential = None 
  
    ##
    # Create a new slice manager object.
    #
    # @param ip the ip address to listen on
    # @param port the port to listen on
    # @param key_file private key filename of registry
    # @param cert_file certificate filename containing public key (could be a GID file)     

    def __init__(self, ip, port, key_file, cert_file, config = "/usr/share/geniwrapper/geni/util/geni_config"):
        GeniServer.__init__(ip, port, key_file, cert_file)
        self.key_file = key_file
        self.cert_file = cert_file
        self.conf = Config(config)
        basedir = self.conf.GENI_BASE_DIR + os.sep
        server_basedir = basedir + os.sep + "geni" + os.sep
        self.hrn = conf.GENI_INTERFACE_HRN    

        # Get list of aggregates this sm talks to
        # XX do we use simplestorage to maintain this file manually?
        aggregates_file = server_basedir + os.sep + 'aggregates'
        self.aggregates = SimpleStorage(aggregates_file)
        self.connect_aggregates(aggregates_file) 
        
        nodes_file = os.sep.join([server_basedir, 'smgr.' + self.hrn + '.components'])
        self.nodes = SimpleStorage(nodes_file)
        self.nodes.load()
        
        slices_file = os.sep.join([server_basedir, 'smgr' + self.hrn + '.slices'])
        self.slices = SimpleStorage(slices_file)
        self.slices.load()

        policy_file = os.sep.join([server_basedir, 'smgr.' + self.hrn + '.policy'])
        self.policy = SimpleStorage(policy_file)
        self.policy.load()

        timestamp_file = os.sep.join([server_basedir, 'smgr.' + self.hrn + '.timestamp'])
        self.timestamp = SimpleStorage(timestamp_file)
 
        self.nodes_ttl = 1
        self.connectAggregates()
        self.connectRegistry()
        self.loadCredential()


    def loadCredential(self):
        """
        Attempt to load credential from file if it exists. If it doesnt get
        credential from registry.
        """

        self_cred_filename = self.server_basedir + os.sep + "smgr." + self.hrn + ".cred"
        ma_cred_filename = self.server_basedir + os.sep + "smgr." + self.hrn + ".sa.cred"

        # see if this file exists
        try:
            cred = Credential(filename = ma_cred_filename)
            self.credential = cred.save_to_string()
        except IOError:
            # get self credential
            self_cred = self.registry.get_credential(None, 'ma', self.hrn)
            self_credential = Credential(string = self_cred)
            self_credential.save_to_file(self_cred_filename)

            # get ma credential
            ma_cred = self.registry.get_gredential(self_cred)
            ma_credential = Credential(string = ma_cred)
            ma_credential.save_to_file(ma_cred_filename)
            self.credential = ma_cred        

    def connect_aggregates(self, aggregates_file):
        """
        Get info about the aggregates available to us from file and create 
        an xmlrpc connection to each. If any info is invalid, skip it. 
        """
        lines = []
        try:
            f = open(aggregates_file, 'r')
            lines = f.readlines()
            f.close()
        except: raise 
    
        for line in lines:
            # Skip comments
            if line.strip.startswith("#"):
                continue
            agg_info = line.split("\t").split(" ")
        
            # skip invalid info
            if len(agg_info) != 3:
                continue

            # create xmlrpc connection using GeniClient
            hrn, address, port = agg_info[0], agg_info[1], agg_info[2]
            url = 'https://%(address)s:%(port)s' % locals()
            self.aggregates[hrn] = GeniClient(url, self.key_file, self.cert_file)


    def item_hrns(self, items):
        """
        Take a list of items (components or slices) and return a dictionary where
        the key is the authoritative hrn and the value is a list of items at that 
        hrn.
        """
        item_hrns = {}
        agg_hrns = self.aggregates.keys()
        for agg_hrn in agg_hrns:
            item_hrns[agg_hrn] = []
        for item in items:
            for agg_hrn in agg_hrns:
                if item.startswith(agg_hrn):
                    item_hrns[agg_hrn] = item

        return item_hrns    
             

    def hostname_to_hrn(self, login_base, hostname):
        """
        Convert hrn to plantelab name.
        """
        genihostname = "_".join(hostname.split("."))
        return ".".join([self.hrn, login_base, genihostname])

    def slicename_to_hrn(self, slicename):
        """
        Convert hrn to planetlab name.
        """
        slicename = slicename.replace("_", ".")
        return ".".join([self.hrn, slicename])

    def refresh_components(self):
        """
        Update the cached list of nodes.
        """
        print "refreshing"
    
        aggregates = self.aggregates.keys()
        all_nodes = []
        nodedict = {}
        for aggregate in aggregates:
            try:
                # resolve components hostnames
                nodes = self.aggregates[aggregate].get_components()
                all_nodes.extend(nodes)    
            except:
                # XX print out to some error log
                pass    
   
        for node in all_nodes:
            if self.polciy['whitelist'] and node not in self.polciy['whitelist']:
                continue
            if self.polciy['blacklist'] and node in self.policy['blacklist']:
                continue

            nodedict[node] = node

        self.nodes = SimpleStorate(self.nodes.db_filename, nodedict)
        self.nodes.write()

        # update timestamp and threshold
        self.timestamp['timestamp'] = datetime.datetime.now()
        delta = datetime.timedelta(hours=self.nodes_tt1)
        self.threshold = self.timestamp['timestamp'] + delta
        self.timestamp.write()
        
 
    def load_components(self):
        """
        Read cached list of nodes and slices.
        """
        print "loading nodes"
        # Read component list from cached file 
        self.nodes.load()
        self.timestamp.load()
        time_format = "%Y-%m-%d %H:%M:%S"
        timestamp = self.timestamp['timestamp']
        self.timestamp['timestamp'] = datetime.datetime.fromtimestamp(time.mktime(time.strptime(timestamp, time_format)))
        delta = datetime.timedelta(hours=self.nodes_ttl)
        self.threshold = self.timestamp['timestamp'] + delta

    def load_policy(self):
        """
        Read the list of blacklisted and whitelisted nodes.
        """
        self.policy.load()
 
    def load_slices(self):
        """
        Read current slice instantiation states.
        """
        print "loading slices"
        self.slices.load()


    def getComponents(self):
        """
        Return a list of components managed by this slice manager.
        """
        # Reload components list
        now = datetime.datetime.now()
        #self.load_components()
        if not self.threshold or not self.timestamp or now > self.threshold:
            self.refresh_components()
        elif now < self.threshold and not self.components: 
            self.load_components()
        return self.nodes.keys()
   
     
    def getSlices(self):
        """
        Return a list of instnatiated managed by this slice manager.
        """
        # XX return only the slices at the specified hrn
        return dict(self.slices)

    def getResources(self, slice_hrn):
        """
        Return the current rspec for the specified slice.
        """
        cred = self.credential

        if slice_hrn in self.slices.keys():
            # check if we alreay have this slices state saved
            rspec = self.slices[slice_hrn]
        else:
            # request this slices state from all  known aggregates
            rspecdicts = []
            for hrn in self.aggregates.keys():
                # XX need to use the right credentials for this call
                # check if the slice has resources at this hrn
                tempresources = self.aggregates[hrn].resources(cred, slice_hrn)
                temprspec = Rspec()
                temprspec.parseString(temprspec)
                if temprspec.getDictsByTagName('NodeSpec'):
                    # append this rspec to the list of rspecs
                    rspecdicts.append(temprspec.toDict())
                
            # merge all these rspecs into one
            start_time = int(self.timestamp['timestamp'].strftime("%s"))
            end_time = int(self.duration.strftime("%s"))
            duration = end_time - start_time
                
            # create a plc dict 
            networks = [rspecdict['networks'][0] for rspecdict in rspecdicts]
            resources = {'networks': networks, 'start_time': start_time, 'duration': duration}
            # convert the plc dict to an rspec dict
            resourceDict = RspecDict(resources)
            resourceSpec = Rspec()
            resourceSpec.parseDict(resourceDict)
            rspec = resourceSpec.toxml() 
            # save this slices resources
            self.slices[slice_hrn] = rspec
            self.slices.write()
         
        return rspec
 
    def createSlice(self, slice_hrn, rspec, attributes):
        """
        Instantiate the specified slice according to whats defined in the rspec.
        """
        # XX need to gget the correct credentials
        cred = self.credential

        # save slice state locally
        # we can assume that spec object has been validated so its safer to
        # save this instead of the unvalidated rspec the user gave us
        self.slices[slice_hrn] = spec.toxml()
        self.slices.write()

        # extract network list from the rspec and create a separate
        # rspec for each network
        slicename = self.hrn_to_plcslicename(slice_hrn)
        spec = Rspec()
        spec.parseString(rspec)
        specDict = spec.toDict()
        start_time = specDict['start_time']
        end_time = specDict['end_time']

        rspecs = {}
        # only attempt to extract information about the aggregates we know about
        for hrn in self.aggregates.keys():
            netspec = spec.getDictByTagNameValue('NetSpec', 'hrn')
            if netspec:
                # creat a plc dict 
                tempdict = {'start_time': star_time, 'end_time': end_time, 'networks': netspec}
                #convert the plc dict to rpsec dict
                resourceDict = RspecDict(tempdict)
                # parse rspec dict
                tempspec = Rspec()
                tempspec.parseDict(resourceDict)
                rspecs[hrn] = tempspec.toxml()

        # notify the aggregates
        for hrn in self.rspecs.keys():
            self.aggregates[hrn].createSlice(cred, rspecs[hrn])
            
        return 1

    def updateSlice(self, slice_hrn, rspec, attributes = []):
        """
        Update the specifed slice
        """
        self.create_slice(slice_hrn, rspec, attributes)
    
    def deleteSlice_(self, slice_hrn):
        """
        Remove this slice from all components it was previouly associated with and 
        free up the resources it was using.
        """
        # XX need to get the correct credential
        cred = self.credential
        
        if self.slices.has_key(slice_hrn):
            self.slices.pop(slice_hrn)
            self.slices.write()

        for hrn in self.aggregates.keys():
            self.aggregates[hrn].deleteSlice(cred, slice_hrn)

        return 1

    def startSlice(self, slice_hrn):
        """
        Stop the slice at plc.
        """
        cred = self.credential

        for hrn in self.aggregates.keys():
            self.aggregates[hrn].startSlice(cred, slice_hrn)
        return 1

    def stopSlice(self, slice_hrn):
        """
        Stop the slice at plc
        """
        cred = self.credential
        for hrn in self.aggregates.keys():
            self.aggregates[hrn].startSlice(cred, slice_hrn)
        return 1

    def resetSlice(self, slice_hrn):
        """
        Reset the slice
        """
        # XX not yet implemented
        return 1

    def getPolicy(self):
        """
        Return the policy of this slice manager.
        """
    
        return self.policy
        
    

##############################
## Server methods here for now
##############################

    def list_components(self):
        return self.getComponents()

    def list_slices(self, cred, hrn):
        self.decode_authentication(cred, 'list')
        return self.getSlices(hrn)

    def get_resources(self, cred, hrn):
        self.decode_authentication(cred, 'info')
        return self.getResources(hrn)

    def get_policy(self, cred):
        self.decode_authentication(cred, 'info')
        return self.getPolicy()

    def create_slice(self, cred, hrn, rspec):
        self.decode_authentication(cred, 'embed')
        return self.createSlice(hrn)

    def delete_slice(self, cred, hrn):
        self.decode_authentication(cred, 'embed')
        return self.deleteSlice(hrn)

    def start_slice(self, cred, hrn):
        self.decode_authentication(cred, 'control')
        return self.startSlice(hrn)

    def stop_slice(self, cred, hrn):
        self.decode_authentication(cred, 'control')
        return self.stopSlice(hrn)

    def reset_slice(self, cred, hrn):
        self.decode_authentication(cred, 'control')
        return self.resetSlice(hrn)

    def register_functions(self):
        GeniServer.register_functions(self)

        # Aggregate interface methods
        self.server.register_function(self.list_components)
        self.server.register_function(self.list_slices)
        self.server.register_function(self.get_resources)
        self.server.register_function(self.get_policy)
        self.server.register_function(self.create_slice)
        self.server.register_function(self.delete_slice)
        self.server.register_function(self.start_slice)
        self.server.register_function(self.stop_slice)
        self.server.register_function(self.reset_slice)
              
