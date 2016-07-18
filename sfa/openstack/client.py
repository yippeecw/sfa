from sfa.util.config import Config
try:
    from keystoneclient.v2_0 import client as keystone_client
    from novaclient.v2 import client as nova_client
    from neutronclient.v2_0 import client as neutron_client
    from heatclient.v1 import client as heat_client
except:
    from sfa.util.faults import SfaNotImplemented
    raise SfaNotImplemented('OpenStack Import')

def parse_accrc(filename):
    opts = {}
    f = open(filename, 'r')
    for line in f:
        try:
            line = line.replace('export', '').strip()
            parts = line.split('=')
            if len(parts) > 1:
                value = parts[1].replace("\'", "")
                value = value.replace('\"', '') 
                opts[parts[0]] = value
        except:
            pass
    f.close()
    return opts

class KeystoneClient:
    def __init__(self, username=None, password=None, tenant=None, url=None, config=None):
        if not config:
            config = Config()
        opts = parse_accrc(config.SFA_NOVA_NOVARC)
        if not username: username=opts['OS_USERNAME']
        if not password: password=opts['OS_PASSWORD']
        if not tenant:   tenant=opts['OS_TENANT_NAME']
        if not url:      url=opts['OS_AUTH_URL']
        self.client = keystone_client.Client(username=username, password=password, tenant_name=tenant, auth_url=url)

    def connect(self, *args, **kwds):
        self.__init__(*args, **kwds)
   
    def __getattr__(self, name):
        return getattr(self.client, name) 

class NovaClient:
    def __init__(self, username=None, password=None, tenant=None, url=None, config=None):
        if not config:
            config = Config()
        opts = parse_accrc(config.SFA_NOVA_NOVARC)
        if not username: username=opts['OS_USERNAME']
        if not password: password=opts['OS_PASSWORD']
        if not tenant:   tenant=opts['OS_TENANT_NAME']
        if not url:      url=opts['OS_AUTH_URL']
        self.client = nova_client.Client(username=username, api_key=password, project_id=tenant, auth_url=url,
                                         region_name='',
                                         extensions=[],
                                         service_type='compute',
                                         service_name='',  
                                         )

    def connect(self, *args, **kwds):
        self.__init__(*args, **kwds)
                              
    def __getattr__(self, name):
        return getattr(self.client, name)

class NeutronClient:
    def __init__(self, username=None, password=None, tenant=None, url=None, config=None):
        if not config:
            config = Config()
        opts = parse_accrc(config.SFA_NOVA_NOVARC)
        if not username: username=opts['OS_USERNAME']
        if not password: password=opts['OS_PASSWORD']
        if not tenant:   tenant=opts['OS_TENANT_NAME']
        if not url:      url=opts['OS_AUTH_URL']
        self.client = neutron_client.Client(username=username, password=password, tenant_name=tenant, auth_url=url)

    def connect(self, *args, **kwds):
        self.__init__(*args, **kwds)

    def __getattr__(self, name):
        return getattr(self.client, name)

class HeatClient:
    def __init__(self, username=None, password=None, tenant=None, url=None, config=None):
        if not config:
            config = Config()
        opts = parse_accrc(config.SFA_NOVA_NOVARC)
        if not username: username=opts['OS_USERNAME']
        if not password: password=opts['OS_PASSWORD']
        if not tenant:   tenant=opts['OS_TENANT_NAME']
        if not url:      url=opts['OS_AUTH_URL']
        keystone = KeystoneClient(username=username, password=password, tenant=tenant, url=url)
        self.client = heat_client.Client(username=username, password=password, token=keystone.auth_token,
                                         endpoint=keystone.auth_ref.service_catalog.get_urls(service_type='orchestration')[0])

    def connect(self, *args, **kwds):
        self.__init__(*args, **kwds)

    def __getattr__(self, name):
        return getattr(self.client, name)
