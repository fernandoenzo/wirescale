#!/usr/bin/env python3
# encoding:utf-8


class IPTABLES:
    COMMENT_TEMPLATE = '-m comment --comment "wirescale-{interface}"'

    INPUT_ACCEPT_INTERFACE = 'iptables -I INPUT -i %i -j ACCEPT ' + COMMENT_TEMPLATE
    INPUT_ACCEPT_PORT = 'iptables -I INPUT -p udp --dport {port} -j ACCEPT ' + COMMENT_TEMPLATE
    FORWARD = 'iptables -I FORWARD -i %i -j ACCEPT ' + COMMENT_TEMPLATE
    FORWARD_MARK = 'iptables -I FORWARD -i %i -j MARK --set-mark {mark} ' + COMMENT_TEMPLATE
    MASQUERADE = 'iptables -t nat -I POSTROUTING ! -o %i -m mark --mark {mark} -j MASQUERADE ' + COMMENT_TEMPLATE
    SAVE_CONNMARK = 'iptables -t mangle -I POSTROUTING -m mark --mark {mark} -p udp -j CONNMARK --save-mark ' + COMMENT_TEMPLATE
    RESTORE_CONNMARK = 'iptables -t mangle -I PREROUTING -p udp -j CONNMARK --restore-mark ' + COMMENT_TEMPLATE

    @staticmethod
    def remove_rule(rule: str) -> str:
        return f"{rule.replace('-I', '-D', 1)} || true"
