#!/usr/bin/env python

__all__ = ['IPv4Match', 'IPv6Match', 'TCPMatch', 'UDPMatch', 'EthMatch', 'MUDMatch']


class IPv4Match:
    def __init__(self, json_obj):
        self._json_obj = json_obj
        self.protocol = ''
        self.mud_dst_dnsname = ''
        # TODO: add all other fields in ACL yang data model (draft-ietf-netmod-acl-model)
        self.__parse()

    def __parse(self):
        obj = self._json_obj
        keys = obj.keys()
        for key in keys:
            if key is 'protocol':
                self.protocol = obj[key]
            elif key is 'ietf-acldns:dst-dnsname':
                self.mud_dst_dnsname = obj[key]


class IPv6Match:
    def __init__(self, json_obj):
        # TODO: add all other fields in ACL yang data model (draft-ietf-netmod-acl-model)
        self._json_obj = json_obj


class Port:
    def __init__(self, operator='', port=-1):
        # this supports operator only
        # TODO: support port range as well
        self.operator = operator
        self.port = port


class TCPMatch:
    def __init__(self, json_obj):
        self._json_obj = json_obj
        self.dst_port = None
        self.mud_direction_init = ''
        # TODO: add all other fields in ACL yang data model (draft-ietf-netmod-acl-model)
        self.__parse()

    def __parse(self):
        obj = self._json_obj
        tcp_keys = obj.keys()
        for tcp_key in tcp_keys:
            if tcp_key == 'destination-port':
                port_keys = obj[tcp_key].keys()
                port = Port()
                for port_key in port_keys:
                    if port_key == 'operator':
                        port.operator = obj[tcp_key][port_key]
                    elif port_key == 'port':
                        port.port = obj[tcp_key][port_key]
                self.dst_port = port
            elif tcp_key == 'ietf-mud:direction-initiated':
                self.mud_direction_init = obj[tcp_key]


class UDPMatch:
    def __init__(self, json_obj):
        self._json_obj = json_obj
        self.dst_port = None
        # TODO: add all other fields in ACL yang data model (draft-ietf-netmod-acl-model)
        self.__parse()

    def __parse(self):
        pass


class EthMatch:
    def __init__(self, json_obj):
        self._json_obj = json_obj
        self.__parse()

    def __parse(self):
        pass


class MUDMatch:
    def __init__(self, json_obj):
        self._json_obj = json_obj
        self.key = ''
        self.value = ''
        # TODO: add all other fields in ACL yang data model (draft-ietf-netmod-acl-model)
        self.__parse()

    def __parse(self):
        obj = self._json_obj
        mud_keys = obj.keys()
        # TODO: one key only or multiple?
        # if one key only
        mud_key = mud_keys[0]
        # checking type of object in mud match
        if mud_key == 'manufacturer':
            assert (isinstance(obj[self.key], str))
        elif mud_key == 'same-manufacturer':
            # should be empty list. see rfc https://datatracker.ietf.org/doc/draft-ietf-opsawg-mud/
            assert (type(obj[self.key]) == list and len(obj[self.key]) == 0)
        elif mud_key == 'model':
            assert (isinstance(obj[self.key], str))
        elif mud_key == 'local-networks':
            # should be empty list. see rfc https://datatracker.ietf.org/doc/draft-ietf-opsawg-mud/
            assert (type(obj[self.key]) == list and len(obj[self.key]) == 0)
        elif mud_key == 'controller':
            assert (isinstance(obj[self.key], str))
        elif mud_key == 'my-controller':
            # should be empty list. see rfc https://datatracker.ietf.org/doc/draft-ietf-opsawg-mud/
            assert (type(obj[self.key]) == list and len(obj[self.key]) == 0)
        self.value = obj[self.key]

        # if multiple keys, need keys array in self
        # for mud_key in mud_keys:
        #     if mud_key == 'manufacturer':
        #         pass
        #     elif mud_key == 'same-manufacturer':
        #         pass
        #     elif mud_key == 'model':
        #         pass
        #     elif mud_key == 'local-networks':
        #         pass
        #     elif mud_key == 'controller':
        #         pass
        #     elif mud_key == 'my-controller':
        #         pass



