#!/usr/bin/env python

"""Profile object representing the mud file profile.
Reads a json formatted file and returns an object.
"""

import json
import os
from mudparser.acl import AccessList

__all__ = ['Profile']


class Profile:
    def __init__(self, file, autoparse=True):
        self._file = file
        self.version = 0
        self.url = ''
        self.last_update = ''
        self.cache_validity = 0
        self.is_supported = False
        self.system_info = ''
        self.policies = {}
        self.acls = {}
        if autoparse:
            self.parse()

    def parse(self):  # make this private maybe and get rid of autoparse?
        json_obj = json.load(self._file)
        # parse ACLs related info first, they will be stored in dictionary self.acls
        # and pointed to in object self.policies dictionary
        acls_json_obj = json_obj["ietf-access-control-list:access-lists"]
        self.__parse_acls(acls_json_obj)
        # parse MUD related info
        mud_json_obj = json_obj["ietf-mud:mud"]
        self.__parse_mud(mud_json_obj)

    # private method to parse acls container in mud profile
    def __parse_acls(self, json_obj):
        for acl in json_obj['acl']:
            access_list = AccessList(acl)
            self.acls[access_list.name] = access_list

    # private method to parse mud container in mud profile
    def __parse_mud(self, json_obj):
        self.version = json_obj["mud-version"]
        self.url = json_obj["mud-url"]
        self.last_update = json_obj["last-update"]
        self.cache_validity = json_obj["cache-validity"]
        self.is_supported = json_obj["is-supported"]
        self.system_info = json_obj["systeminfo"]

        # TODO: supported commented below, they are not included in current json test files
        # self.mfg_name = json_obj["mfg-name"]
        # self.model_name = json_obj["model-name"]
        # self.firmware_rev = json_obj["firmware-rev"]
        # self.software_rev = json_obj["software-rev"]
        # self.extensions = json_obj["extensions"]

        from_dev_policy_acls_obj = json_obj["from-device-policy"]["access-lists"]
        policy_acls = {}  # a dict that will hold the acls for from-device-policy
        for acl_obj in from_dev_policy_acls_obj["access-list"]:
            acl_name = acl_obj["name"]
            acl, found = self.__lookup_acl(acl_name)
            if found:
                policy_acls[acl_name] = acl
            else:
                print('json file missing acl with name "{}"'.format(acl_obj["name"]))
                os._exit(1)
        self.policies["from-device-policy"] = policy_acls
        to_dev_policy_acls_obj = json_obj["to-device-policy"]["access-lists"]

        policy_acls = {}  # a dict that will hold the acls for to-device-policy
        for acl_obj in to_dev_policy_acls_obj["access-list"]:
            acl_name = acl_obj["name"]
            acl, found = self.__lookup_acl(acl_name)
            if found:
                policy_acls[acl_name] = acl
            else:
                print('json file missing acl with name "{}"'.format(acl_obj["name"]))
                os._exit(1)
        self.policies["to-device-policy"] = policy_acls

    def __lookup_acl(self, name):
        try:
            acl = self.acls[name]
        except KeyError:
            return None, False
        else:
            return acl, True

    def from_dev_policy(self):
        return self.policies['from-device-policy']

    def to_dev_policy(self):
        return self.policies['to-device-policy']

    def access_list(self, acl_name):
        # This method returns an as well as the policy that uses it
        # Return None, None if acl is not found
        policy_name = self.__which_policy(acl_name)
        # TODO: maybe add this direction(from/to) as attribute for acl object
        if policy_name is not None:
            if policy_name == 'from-device-policy':
                return self.acls[acl_name], 'from'
            elif policy_name == 'to-device-policy':
                return self.acls[acl_name], 'to'
        return None, None

    def __which_policy(self, acl_name):
        for policy_key, policy_acls in self.policies.items():
            for name, acls in policy_acls.items():
                if acl_name == name:
                    return policy_key
        return None

    def print_rules(self):
        for policy_key, policy_acls in self.policies.items():
            for name, acl in policy_acls.items():
                if policy_key == 'from-device-policy':
                    acl.print_rules('from')
                elif policy_key == 'to-device-policy':
                    acl.print_rules('to')


if __name__ == '__main__':
    with open('../data/amazon_echo_short.json') as json_file:
        profile = Profile(json_file)
        # print(profile.from_dev_policy())
        # print(profile.to_dev_policy())
        # print(profile.access_lists())
        # print(profile.access_list('from-ipv4-amazonecho').entries())
        # for key, entry in profile.access_list('from-ipv4-amazonecho').entries().items():
        #     print(entry.actions())
    acl, direction = profile.access_list('from-ipv4-amazonecho')
    acl.print_rules(direction)
    profile.print_rules()
