#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from typing import Any, Dict, Optional
from .agent_based_api.v1.type_defs import CheckResult, StringTable, DiscoveryResult
from .agent_based_api.v1 import register, Result, Service, State


Section = Dict[str, Any]

def parse_cisco_ucm_services(string_table: StringTable) -> Optional[Section]:
    if not string_table:
        return None

    by_state: Dict = {}
    all_services_ok = True
    svc_state = []
    for name, status, reason_code, reason_str in string_table:
        by_state.setdefault(status, 0)
        by_state[status] += 1
        s = f"{name}: {status}"
        if reason_str:
            s += " (" + reason_str + ")"
        if status != 'Started' and reason_str != 'Service Not Activated':
            svc_state.append( (State.CRIT, s) )
            all_services_ok = False
        else:
            svc_state.append( (State.OK, s) )

    section: Section = {
        'num_started_services': by_state.get('Started', 0),
        'all_services_ok': all_services_ok,
        'service_state': svc_state,
    }

    return section

def discover_cisco_ucm_services(section: Section) -> DiscoveryResult:
    if section['num_started_services']:
        yield Service()

def check_cisco_ucm_services(section: Section) -> CheckResult:
    if section['all_services_ok']:
        yield Result(state = State.OK, summary = 'All services are OK')
    else:
        yield Result(state = State.CRIT, summary = 'Some services are in bad state')
    for state, s in section['service_state']:
        yield Result(state = state, notice = s)


register.agent_section(
    name = "cisco_ucm_services",
    parse_function = parse_cisco_ucm_services,
)

register.check_plugin(
    name = "cisco_ucm_services",
    service_name = "Services",
    check_function = check_cisco_ucm_services,
    discovery_function = discover_cisco_ucm_services,
)
