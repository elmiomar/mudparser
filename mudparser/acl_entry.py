#!/usr/bin/env python

from mudparser.matches import (IPv4Match, IPv6Match, TCPMatch, UDPMatch, EthMatch, MUDMatch)

__all__ = ['AccessListEntry']


class AccessListEntry:
    def __init__(self, json_obj):
        self._json_obj = json_obj
        self.name = ''
        self.matches = {}
        self.actions = {}
        self.__parse()

    def __parse(self):
        obj = self._json_obj
        self.name = obj['name']
        matches_obj = obj['matches']
        matches_keys = matches_obj.keys()
        for matches_key in matches_keys:
            self.__add_match(match_on=matches_key, json_obj=matches_obj[matches_key])

        actions_obj = obj['actions']
        actions_keys = actions_obj.keys()
        for actions_key in actions_keys:
            self.__add_action(action_type=actions_key, action_name=actions_obj[actions_key])

    def __add_action(self, action_type, action_name):
        self.actions[action_type] = action_name

    def __add_match(self, match_on, json_obj):
        if match_on == 'ipv4':
            self.matches['ipv4'] = IPv4Match(json_obj)
        elif match_on == 'ipv6':
            self.matches['ipv6'] = IPv6Match(json_obj)
        elif match_on == 'udp':
            self.matches['udp'] = UDPMatch(json_obj)
        elif match_on == 'tcp':
            self.matches['tcp'] = TCPMatch(json_obj)
        elif match_on == 'eth':
            self.matches['eth'] = EthMatch(json_obj)
        elif match_on == 'ietf-mud:mud':
            self.matches['mud'] = MUDMatch(json_obj)

    def print_rules(self, direction):
        rule = "[" + direction + "] "  # "[" + self.name + "] "
        for k, a in self.actions.items():
            if k == 'logging':
                pass
            elif k == 'forwarding':
                rule += a + " "
                for k, match in self.matches.items():
                    if k == 'tcp':
                        if direction == 'to':
                            rule += "tcp from" + str(match.src_port.port) + " to any"
                        elif direction == 'from':
                            rule += "tcp from any to " + str(match.dst_port.port)
                    elif k == 'udp':
                        if direction == 'to':
                            rule += "udp from" + str(match.src_port.port) + " to any"
                        elif direction == 'from':
                            rule += "udp from any to " + str(match.dst_port.port)
                    elif k == 'eth':
                        rule += "ethertype " + match.ethertype
        print(rule)
        # TODO: is __str__() better in this case?


