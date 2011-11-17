from sfa.rspecs.elements.element import Element  
from sfa.rspecs.elements.execute import Execute  
from sfa.rspecs.elements.install import Install  
from sfa.rspecs.elements.login import Login

class PGv2Services:
    @staticmethod
    def add_services(xml, services):
        if not services:
            return 
        for service in services:
            service_elem = xml.add_element('services')
            child_elements = {'install': Install.fields,
                              'execute': Execute.fields,
                              'login': Login.fields}
            for (name, fields) in child_elements.items():
                objects = service.get(name)
                if not objects: 
                    continue
                if isinstance(objects, basestring):
                    service_elem.add_instance(name, objects, fields)
                elif isinstance(objects, list):
                    for obj in objects:
                        service_elem.add_instance(name, obj, fields)
              
    @staticmethod
    def get_services(xml):
        services = []
        for services_elem in xml.xpath('./default:services | ./services'):
            service = Services(services_elem.attrib, services_elem)
            # get install 
            install_elems = xml.xpath('./default:install | ./install')
            service['install'] = [install_elem.get_instance(Install) for install_elem in install_elems]
            # get execute
            execute_elems = xml.xpath('./default:execute | ./execute')
            service['execute'] = [execute_elem.get_instance(Execute) for execute_elem in execute_elems]
            # get login
            login_elems = xml.xpath('./default:login | ./login')
            service['login'] = [login_elem.get_instance(Login) for login_elem in login_elems]
            services.append(service)  
        return services

