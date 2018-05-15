#!/usr/bin/env python

"""Profile object representing the mud file profile.
Reads a json formatted file and returns an object.
"""

import json
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

        # TODO: test case these. They are not included in current test files
        # self.mfg_name = json_obj["mfg-name"]
        # self.model_name = json_obj["model-name"]
        # self.firmware_rev = json_obj["firmware-rev"]
        # self.software_rev = json_obj["software-rev"]
        # self.extensions = json_obj["extensions"]

        from_dev_policy_acls_obj = json_obj["from-device-policy"]["access-lists"]
        acl_names = []
        for acl_obj in from_dev_policy_acls_obj["access-list"]:
            acl_names.append(acl_obj["name"])
        self.policies["from-device-policy"] = acl_names
        to_dev_policy_acls_obj = json_obj["to-device-policy"]["access-lists"]
        acl_names = []
        for acl_obj in to_dev_policy_acls_obj["access-list"]:
            acl_names.append(acl_obj["name"])
        self.policies["to-device-policy"] = acl_names

    def from_dev_policy(self):
        return self.policies['from-device-policy']

    def to_dev_policy(self):
        return self.policies['to-device-policy']

    def access_list(self, key):
        return self.acls[key]
