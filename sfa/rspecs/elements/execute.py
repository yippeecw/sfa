from sfa.rspecs.elements.element import Element

class Execute(Element):
    fields = {
        'shell': None,
        'command': None,
    }