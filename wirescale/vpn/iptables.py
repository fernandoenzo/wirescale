#!/usr/bin/env python3
# encoding:utf-8


class IPTABLES:
    COMMENT_TEMPLATE = '-m comment --comment "wirescale-{interface}"'

    INPUT_ACCEPT_INTERFACE = 'iptables -I INPUT -i %i -j ACCEPT ' + COMMENT_TEMPLATE
    INPUT_ACCEPT_PORT = 'iptables -I INPUT -p udp --dport {port} -j ACCEPT ' + COMMENT_TEMPLATE
    FORWARD = 'iptables -I FORWARD -i %i -j ACCEPT ' + COMMENT_TEMPLATE
    FORWARD_MARK = 'iptables -I FORWARD -i %i -j MARK --set-mark {mark} ' + COMMENT_TEMPLATE
    MASQUERADE = 'iptables -t nat -I POSTROUTING ! -o %i -m mark --mark {mark} -j MASQUERADE ' + COMMENT_TEMPLATE

    @staticmethod
    def remove_rule(rule: str) -> str:
        return rule.replace('-I', '-D', 1)

    @staticmethod
    def or_true(rule: str) -> str:
        return f'{rule} || true'
