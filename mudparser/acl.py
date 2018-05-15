#!/usr/bin/env python

from mudparser.acl_entry import AccessListEntry

__all__ = ['AccessList']


class AccessList:
    def __init__(self, json_obj):
        self._json_obj = json_obj
        self.name = ''
        self.type = ''
        self.entries = {}
        self.__parse()

    def __parse(self):
        obj = self._json_obj
        self.name = obj['name']
        self.type = obj['type']
        for ace in obj['aces']['ace']:
            entry = AccessListEntry(ace)
            self.entries[entry.name] = entry

