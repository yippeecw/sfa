from sfa.rspecs.elements.element import Element  
import types

class OSNode(Element):
    fields = [ 
            'component_id',
            'component_manager_id',
            'heat_template_version',
            'name',
            'node_id',
            'location',
            'status',
            'tags',
            'slivers'
    ]
