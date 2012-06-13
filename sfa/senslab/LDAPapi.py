
import string
import random
from passlib.hash import ldap_salted_sha1 as lssha
from sfa.util.xrn import Xrn,get_authority 
import ldap
from sfa.util.config import Config
#from sfa.trust.gid import *
from sfa.trust.hierarchy import Hierarchy
#from sfa.trust.auth import *
from sfa.trust.certificate import *
import ldap.modlist as modlist
from sfa.util.sfalogging import logger


#API for OpenLDAP

class ldap_co:
    """ Set admin login and server configuration variables."""
    def __init__(self):
        
        #self.login = 'cn=admin,dc=senslab,dc=info'
        #self.passwd = 'sfa'  
        self.server_ip = "194.199.16.161"

        #Senslab PROD LDAP parameters 
        #TODO : Use config file /etc/senslab/config.properties if it is possible
	self.ldapPort = ldap.PORT
	self.ldapVersion  = ldap.VERSION3
	self.ldapSearchScope = ldap.SCOPE_SUBTREE


	self.ldapHost = "" #set ldap.OPT_HOST_NAME maybe ?
	self.ldapPeopleDN = 'ou=People,dc=senslab,dc=info';
	self.ldapGroupDN = 'ou=Group,dc=senslab,dc=info';
	self.ldapAdminDN = 'uid=web,ou=Service,dc=senslab,dc=info';
	self.ldapAdminPassword = 'XNB+1z(C'

    def connect(self, bind = True):
        """Enables connection to the LDAP server.
        Set the bind parameter to True if a bind is needed
        (for add/modify/delete operations).
        Set to False otherwise.
        
        """
        try:
            self.ldapserv = ldap.open(self.server_ip)
        except ldap.LDAPError, e:
            return {'bool' : False, 'message' : e }
        
        # Bind with authentification
        if(bind): 
            return self.bind()
        
        else:     
            return {'bool': True}
    
    
    def bind(self):
        """ Binding method. """
        try:
            # Opens a connection after a call to ldap.open in connect:
            self.ldapserv = ldap.initialize("ldap://" + self.server_ip )
                
            # Bind/authenticate with a user with apropriate rights to add objects
            self.ldapserv.simple_bind_s(self.ldapAdminDN, self.ldapAdminPassword)

        except ldap.LDAPError, e:
            return {'bool' : False, 'message' : e }

        return {'bool': True}
    
    def close(self):
        """ Close the LDAP connection """
        try:
            self.ldapserv.unbind_s()
        except ldap.LDAPError, e:
            return {'bool' : False, 'message' : e }
            
        
class LDAPapi :
    def __init__(self):
        logger.setLevelDebug() 
        #SFA related config
        self.senslabauth=Hierarchy()
        config=Config()
        
        self.authname=config.SFA_REGISTRY_ROOT_AUTH
        #self.baseDN = "ou=people,dc=senslab,dc=info"
        self.conn =  ldap_co()  
        self.baseDN = self.conn.ldapPeopleDN
        #authinfo=self.senslabauth.get_auth_info(self.authname)
        
        
        self.charsPassword = [ '!','$','(',')','*','+',',','-','.',\
                                '0','1','2','3','4','5','6','7','8','9',\
                                'A','B','C','D','E','F','G','H','I','J',\
                                'K','L','M','N','O','P','Q','R','S','T',\
                                'U','V','W','X','Y','Z','_','a','b','c',\
                                'd','e','f','g','h','i','j','k','l','m',\
                                'n','o','p','q','r','s','t','u','v','w',\
                                'x','y','z','\'']
        self.ldapUserQuotaNFS = '/dev/vdb:2000000:2500000:0:0'
        self.lengthPassword = 8;
        self.ldapUserHomePath = '/senslab/users/' 
        self.ldapUserGidNumber = '2000'
        self.ldapUserUidNumberMin = '2000' 
        self.ldapShell = '/bin/bash'
        #self.auth=Auth()
        #gid=authinfo.get_gid_object()
        #self.ldapdictlist = ['type',
                        #'pkey',
                        #'uid',
                        #'serial',
                        #'authority',
                        #'peer_authority',
                        #'pointer' ,
                        #'hrn']
          
                        
    
    def generate_login(self, record):
        """Generate login for adding a new user in LDAP Directory 
        (four characters minimum length)
        Record contains first name and last name.
        
        """ 
        #Remove all special characters from first_name/last name
        lower_first_name = record['first_name'].replace('-','')\
                                        .replace('_','').replace('[','')\
                                        .replace(']','').replace(' ','')\
                                        .lower()
        lower_last_name = record['last_name'].replace('-','')\
                                        .replace('_','').replace('[','')\
                                        .replace(']','').replace(' ','')\
                                        .lower()  
        length_last_name = len(lower_last_name)
        login_max_length = 8
        
        #Try generating a unique login based on first name and last name
        getAttrs = ['uid']
        if length_last_name >= login_max_length :
            login = lower_last_name[0:login_max_length]
            index = 0;
            logger.debug("login : %s index : %s" %(login,index))
        elif length_last_name >= 4 :
            login = lower_last_name
            index = 0
            logger.debug("login : %s index : %s" %(login,index))
        elif length_last_name == 3 :
            login = lower_first_name[0:1] + lower_last_name
            index = 1
            logger.debug("login : %s index : %s" %(login,index))
        elif length_last_name == 2:
            if len ( lower_first_name) >=2:
                login = lower_first_name[0:2] + lower_last_name
                index = 2
                logger.debug("login : %s index : %s" %(login,index))
            else:
                logger.error("LoginException : \
                            Generation login error with \
                            minimum four characters")
            
                
        else :
            logger.error("LDAP generate_login failed : \
                            impossible to generate unique login for %s %s" \
                            %(lower_first_name,lower_last_name))
            
        filter = '(uid=' + login + ')'
        
        try :
            #Check if login already in use
            while (len(self.LdapSearch(filter, getAttrs)) is not 0 ):
            
                index += 1
                if index >= 9:
                    logger.error("LoginException : Generation login error \
                                    with minimum four characters")
                else:
                    try:
                        login = lower_first_name[0:index] + \
                                    lower_last_name[0:login_max_length-index]
                        filter = '(uid='+ login+ ')'
                    except KeyError:
                        print "lower_first_name - lower_last_name too short"
                        
            logger.debug("LDAP.API \t generate_login login %s" %(login))
            return login
                    
        except  ldap.LDAPError,e :
            logger.log_exc("LDAP generate_login Error %s" %e)
            return None

        

    def generate_password(self):
    
        """Generate password for adding a new user in LDAP Directory 
        (8 characters length) return password
        
        """
        password = str()
        for index in range(self.lengthPassword):
            password += self.charsPassword[random.randint(0, \
                                            len(self.charsPassword))]

        return password

    def encrypt_password(self, password):
       """ Use passlib library to make a RFC2307 LDAP encrypted password
       salt size = 8, use sha-1 algorithm. Returns encrypted password.
       
       """
       #Keep consistency with Java Senslab's LDAP API 
       #RFC2307SSHAPasswordEncryptor so set the salt size to 8 bytres
       return lssha.encrypt(password,salt_size = 8)
    


    def find_max_uidNumber(self):
            
        """Find the LDAP max uidNumber (POSIX uid attribute) .
        Used when adding a new user in LDAP Directory 
        returns string  max uidNumber + 1
        
        """
        #First, get all the users in the LDAP
        getAttrs = "(uidNumber=*)"
        filter = ['uidNumber']

        result_data = self.LdapSearch(getAttrs, filter) 
        #It there is no user in LDAP yet, First LDAP user
        if result_data == []:
            max_uidnumber = self.ldapUserUidNumberMin
        #Otherwise, get the highest uidNumber
        else:
            
            uidNumberList = [int(r[1]['uidNumber'][0])for r in result_data ]
            logger.debug("LDAPapi.py \tfind_max_uidNumber  \
                                    uidNumberList %s " %(uidNumberList))
            max_uidnumber = max(uidNumberList) + 1
            
        return str(max_uidnumber)
        
    #TODO ; Get ssh public key from sfa record   
    #To be filled by N. Turro                
    def get_ssh_pkey(self, record):
        return 'A REMPLIR '
         
         
    #TODO Handle OR filtering in the ldap query when 
    #dealing with a list of records instead of doing a for loop in GetPersons   
    def make_ldap_filters_from_record(self, record=None):
        """
        Helper function to make LDAP filter requests out of SFA records.
        """
        req_ldapdict = {}
        if record :
            if 'first_name' in record  and 'last_name' in record:
                req_ldapdict['cn'] = str(record['first_name'])+" "\
                                        + str(record['last_name'])
            if 'email' in record :
                req_ldapdict['mail'] = record['email']
            if 'mail' in record:
                req_ldapdict['mail'] = record['mail']
                
            if 'hrn' in record :
                splited_hrn = record['hrn'].split(".")
                if splited_hrn[0] != self.authname :
                    logger.warning(" \r\n LDAP.PY \
                        make_ldap_filters_from_record I know nothing \
                        about %s my authname is %s not %s" \
                        %(record['hrn'], self.authname, splited_hrn[0]) )
                        
                login=splited_hrn[1]
                req_ldapdict['uid'] = login
            
            req_ldap=''
            logger.debug("\r\n \t LDAP.PY make_ldap_filters_from_record \
                                record %s req_ldapdict %s" \
                                %(record, req_ldapdict))
            
            for k in req_ldapdict:
                req_ldap += '('+str(k)+'='+str(req_ldapdict[k])+')'
            if  len(req_ldapdict.keys()) >1 :
                req_ldap = req_ldap[:0]+"(&"+req_ldap[0:]
                size = len(req_ldap)
                req_ldap= req_ldap[:(size-1)] +')'+ req_ldap[(size-1):]
        else:
            req_ldap = "(cn=*)"
        
        return req_ldap
        
    def make_ldap_attributes_from_record(self, record):
        """When addind a new user to Senslab's LDAP, creates an attributes 
        dictionnary from the SFA record.
        
        """

        attrs = {}
        attrs['objectClass'] = ["top", "person", "inetOrgPerson",\
                                    "organizationalPerson", "posixAccount",\
                                    "shadowAccount", "systemQuotas",\
                                    "ldapPublicKey"]
        
        attrs['givenName'] = str(record['first_name']).lower().capitalize()
        attrs['sn'] = str(record['last_name']).lower().capitalize()
        attrs['cn'] = attrs['givenName'] + ' ' + attrs['sn']
        attrs['gecos'] = attrs['givenName'] + ' ' + attrs['sn']
        attrs['uid'] = self.generate_login(record)   
                    
        attrs['quota'] = self.ldapUserQuotaNFS 
        attrs['homeDirectory'] = self.ldapUserHomePath + attrs['uid']
        attrs['loginShell'] = self.ldapShell
        attrs['gidNumber'] = '2000'	
        attrs['uidNumber'] = self.find_max_uidNumber()
        attrs['mail'] = record['mail'].lower()
        
        attrs['sshPublicKey'] = self.get_ssh_pkey(record) 
        

        #Password is automatically generated because SFA user don't go 
        #through the Senslab website  used to register new users, 
        #There is no place in SFA where users can enter such information
        #yet.
        #If the user wants to set his own password , he must go to the Senslab 
        #website.
        password = self.generate_password()
        attrs['userPassword']= self.encrypt_password(password)
        
        #Account automatically validated (no mail request to admins)
        #Set to 0 to disable the account, -1 to enable it,
        attrs['shadowExpire'] = '-1'

        #Motivation field in Senslab
        attrs['description'] = 'SFA USER FROM OUTSIDE SENSLAB'
        
        attrs['ou'] = "SFA"         #Optional: organizational unit
        #No info about those here:
        attrs['l'] = 'Grenoble - TBD'#Optional: Locality. 
        attrs['st'] = 'FRANCE - TBD' #Optional: state or province (country).

        return attrs



    def LdapAddUser(self, record = None) :
        """Add SFA user to LDAP if it is not in LDAP  yet. """
        
        user_ldap_attrs = self.make_ldap_attributes_from_record(record)

        
        #Check if user already in LDAP wih email, first name and last name
        filter_by = self.make_ldap_filters_from_record(user_ldap_attrs)
        user_exist = self.LdapSearch(filter_by)
        if user_exist:
            logger.warning(" \r\n \t LDAP LdapAddUser user %s %s already exists" \
                            %(user_ldap_attrs['sn'],user_ldap_attrs['mail'])) 
            return {'bool': False}
        
        #Bind to the server
        result = self.conn.connect()
        
        if(result['bool']):
            
            # A dict to help build the "body" of the object
            
            logger.debug(" \r\n \t LDAP LdapAddUser attrs %s " %user_ldap_attrs)

            # The dn of our new entry/object
            dn = 'uid=' + user_ldap_attrs['uid'] + "," + self.baseDN 

            try:
                ldif = modlist.addModlist(user_ldap_attrs)
                logger.debug("LDAPapi.py add attrs %s \r\n  ldif %s"\
                                %(user_ldap_attrs,ldif) )
                self.conn.ldapserv.add_s(dn,ldif)
                
                logger.info("Adding user %s login %s in LDAP" \
                        %(user_ldap_attrs['cn'] ,user_ldap_attrs['uid']))
                        
                        
            except ldap.LDAPError, e:
                logger.log_exc("LDAP Add Error %s" %e)
                return {'bool' : False, 'message' : e }
        
            self.conn.close()
            return {'bool': True}  
        else: 
            return result

        
    def LdapDelete(self, person_dn):
        """
        Deletes a person in LDAP. Uses the dn of the user.
        """
        #Connect and bind   
        result =  self.conn.connect()
        if(result['bool']):
            try:
                self.conn.ldapserv.delete_s(person_dn)
                self.conn.close()
                return {'bool': True}
            
            except ldap.LDAPError, e:
                logger.log_exc("LDAP Delete Error %s" %e)
                return {'bool': False}
        
    
    def LdapDeleteUser(self, record_filter): 
        """
        Deletes a SFA person in LDAP, based on the user's hrn.
        """
        #Find uid of the  person 
        person = self.LdapFindUser(record_filter,[])
        logger.debug("LDAPapi.py \t LdapDeleteUser record %s person %s" \
        %(record_filter,person))

        if person:
            dn = 'uid=' + person['uid'] + "," +self.baseDN 
        else:
            return {'bool': False}
        
        result = self.LdapDelete(dn)
        return result
        

    def LdapModify(self, dn, old_attributes_dict, new_attributes_dict): 
        """ Modifies a LDAP entry """
         
        ldif = modlist.modifyModlist(old_attributes_dict,new_attributes_dict)
        # Connect and bind/authenticate    
        result = self.conn.connect() 
        if (result['bool']): 
            try:
                self.conn.ldapserv.modify_s(dn,ldif)
                self.conn.close()
                return {'bool' : True }
            except ldap.LDAPError, e:
                logger.log_exc("LDAP LdapModify Error %s" %e)
                return {'bool' : False }
    
        
    def LdapModifyUser(self, user_uid_login, new_attributes_dict):
        """
        Gets the record from one user_uid_login based on record_filter 
        and changes the attributes according to the specified new_attributes.
        Does not use this if we need to modify the uid. Use a ModRDN 
        #operation instead ( modify relative DN )
        """
        if user_uid_login is None:
            logger.error("LDAP \t LdapModifyUser Need user_uid_login  ")
            return {'bool': False} 
        
        #Get all the attributes of the user_uid_login 
        #person = self.LdapFindUser(record_filter,[])
        req_ldap = "(uid=" + user_uid_login + ')'
        person_list = self.LdapSearch(req_ldap, [], bind = True)
        logger.debug("LDAPapi.py \t LdapModifyUser person_list : %s" %(person_list))
        if person_list and len(person_list) > 1 :
            logger.error("LDAP \t LdapModifyUser Too many users returned")
            return {'bool': False}
        if person_list is None :
            logger.error("LDAP \t LdapModifyUser  User %s doesn't exist "\
                        %(user_uid_login))
            return {'bool': False} 
        
        # The dn of our existing entry/object
        #One result only from ldapSearch
        person = person_list[0][1]
        dn  = 'uid=' + person['uid'][0] + "," +self.baseDN  
        if new_attributes_dict:
            old = {}
            for k in new_attributes_dict:
                old[k] =  person[k]
            logger.debug(" LDAPapi.py \t LdapModifyUser  new_attributes %s"\
                                %( new_attributes_dict))  
            result = self.LdapModify(dn, old,new_attributes_dict)
            return result
        else:
            logger.error("LDAP \t LdapModifyUser  No new attributes given. ")
            return {'bool': False} 
            
            
    def LdapResetPassword(self,record):
        """
        Resets password for the user whose record is the parameter and changes
        the corresponding entry in the LDAP.
        
        """
        password = self.generate_password()
        attrs = {}
        attrs['userPassword'] = self.encrypt_password(password)
        logger.debug("LDAP LdapModifyUser Error %s" %e)
        result = self.LdapModifyUser(record, attrs)
        return result
        

    def LdapSearch (self, req_ldap = None, expected_fields = None, bind = False):
        """
        Used to search directly in LDAP, by using ldap filters and
        return fields. 
        When req_ldap is None, returns all the entries in the LDAP.
        
        """
        result = self.conn.connect(bind )
        if (result['bool']) :
            
            return_fields_list = []
            if expected_fields == None : 
                return_fields_list = ['mail','givenName', 'sn', 'uid','sshPublicKey']
            else : 
                return_fields_list = expected_fields
            #No specifc request specified, gert the whole LDAP    
            if req_ldap == None:
               req_ldap = '(cn=*)'
               
            logger.debug("LDAP.PY \t LdapSearch  req_ldap %s \
                            return_fields_list %s" %(req_ldap,return_fields_list))

            try:
                msg_id = self.conn.ldapserv.search(
                                            self.baseDN,ldap.SCOPE_SUBTREE,\
                                            req_ldap,return_fields_list)     
                #Get all the results matching the search from ldap in one 
                #shot (1 value)
                result_type, result_data = \
                                        self.conn.ldapserv.result(msg_id,1)

                self.conn.close()

                logger.debug("LDAP.PY \t LdapSearch  result_data %s"\
                            %(result_data))

                return result_data
            
            except  ldap.LDAPError,e :
                logger.log_exc("LDAP LdapSearch Error %s" %e)
                return []
            
            else:
                logger.error("LDAP.PY \t Connection Failed" )
                return 
            

    def LdapFindUser(self,record = None, expected_fields = None):
        """
        Search a SFA user with a hrn. User should be already registered 
        in Senslab LDAP. 
        Returns one matching entry 
        """   

        req_ldap = self.make_ldap_filters_from_record(record) 
        return_fields_list = []
        if expected_fields == None : 
            return_fields_list = ['mail','givenName', 'sn', 'uid','sshPublicKey']
        else : 
            return_fields_list = expected_fields
            
        result_data = self.LdapSearch(req_ldap,  return_fields_list )
        logger.debug("LDAP.PY \t LdapFindUser  result_data %s" %(result_data))
           
        if len(result_data) is 0:
            return None
        #Asked for a specific user
        if record :
            #try:
            ldapentry = result_data[0][1]
            logger.debug("LDAP.PY \t LdapFindUser ldapentry %s" %(ldapentry))
            tmpname = ldapentry['uid'][0]

            tmpemail = ldapentry['mail'][0]
            if ldapentry['mail'][0] == "unknown":
                tmpemail = None
                    
            #except IndexError: 
                #logger.error("LDAP ldapFindHRn : no entry for record %s found"\
                            #%(record))
                #return None
                
            try:
                hrn = record['hrn']
                parent_hrn = get_authority(hrn)
                peer_authority = None
                if parent_hrn is not self.authname:
                    peer_authority = parent_hrn

                results =  {	
                            'type': 'user',
                            'pkey': ldapentry['sshPublicKey'][0],
                            #'uid': ldapentry[1]['uid'][0],
                            'uid': tmpname ,
                            'email':tmpemail,
                            #'email': ldapentry[1]['mail'][0],
                            'first_name': ldapentry['givenName'][0],
                            'last_name': ldapentry['sn'][0],
                            #'phone': 'none',
                            'serial': 'none',
                            'authority': parent_hrn,
                            'peer_authority': peer_authority,
                            'pointer' : -1,
                            'hrn': hrn,
                            }
            except KeyError,e:
                logger.log_exc("LDAPapi \t LdaFindUser KEyError %s" \
                                %e )
                return
        else:
        #Asked for all users in ldap
            results = []
            for ldapentry in result_data:
                logger.debug(" LDAP.py LdapFindUser ldapentry name : %s " \
                                %(ldapentry[1]['uid'][0]))
                tmpname = ldapentry[1]['uid'][0]
                hrn=self.authname+"."+ tmpname
                
                tmpemail = ldapentry[1]['mail'][0]
                if ldapentry[1]['mail'][0] == "unknown":
                    tmpemail = None

        
                parent_hrn = get_authority(hrn)
                parent_auth_info = self.senslabauth.get_auth_info(parent_hrn)
                try:
                    results.append(  {	
                            'type': 'user',
                            'pkey': ldapentry[1]['sshPublicKey'][0],
                            #'uid': ldapentry[1]['uid'][0],
                            'uid': tmpname ,
                            'email':tmpemail,
                            #'email': ldapentry[1]['mail'][0],
                            'first_name': ldapentry[1]['givenName'][0],
                            'last_name': ldapentry[1]['sn'][0],
                            #'phone': 'none',
                            'serial': 'none',
                            'authority': self.authname,
                            'peer_authority': '',
                            'pointer' : -1,
                            'hrn': hrn,
                            } ) 
                except KeyError,e:
                    logger.log_exc("LDAPapi.PY \t LdapFindUser EXCEPTION %s" %(e))
                    return
        return results   
            
