#!/usr/bin/env python3
# Copyright (C) 2019 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.
import re
from collections.abc import Generator, Mapping, Sequence
from typing import Any, NamedTuple

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Result,
    RuleSetType,
    Service,
    State,
    StringTable,
)



CISCO_UCM_SERVICES_DISCOVERY_DEFAULT_PARAMETERS: dict[str, Any] = {
    "state": "Started",
}

CISCO_UCM_SERVICES_CHECK_DEFAULT_PARAMETERS = {
    "states": [("Started", 0)],
    "else": 2,
    "additional_servicenames": [],
}

CISCO_UCM_SERVICES_SUMMARY_DEFAULT_PARAMETERS = {"ignored": [], "state_if_stopped": 0}


class CUCMService(NamedTuple):
    name: str
    state: str
    reason_code: str
    reason_str: str


Section = list[CUCMService]


def parse_cisco_ucm_services(string_table: StringTable) -> Section:
    return [
        CUCMService(name, state, reason_code, reason_str)
        for name, state, reason_code, reason_str in string_table
    ]

agent_section_cisco_ucm_services = AgentSection(
    name="cisco_ucm_services",
    parse_function=parse_cisco_ucm_services,
)


def discovery_cisco_ucm_services(
        params: list[dict[str, Any]], section: Section
) -> DiscoveryResult:
    # Handle single entries (type str)
    def add_matching_services(service: CUCMService, entry):
        # New wato rule handling
        svc, state = entry
        # First match name (optional since rule based config option available)
        if svc:
            if not svc.startswith("~") and svc != service.name:
                return

            r = re.compile(svc[1:])
            if not r.match(service.name):
                return

        if state and state.lower() != service.state.lower():
            return

        yield Service(item=service.name)

    # Extract the WATO compatible rules for the current host
    rules = []

    for value in params:
        # Now extract the list of service regexes
        svcs = value.get('cisco_ucm_services', [])
        service_state = value.get('state', None)
        if svcs:
            for svc in svcs:
                rules.append(('~' + svc, service_state))
        else:
            rules.append((None, service_state))

    for service in section:
        for rule in rules:
            yield from add_matching_services(service, rule)


def check_cisco_ucm_services_single(
    item: str,
    params: Mapping[str, Any],
    section: Section,
) -> Generator[Result, None, None]:
    additional_names = params.get("additional_servicenames", [])
    for service in section:
        if (item == service.name) or service.name in additional_names:
            summary = f"{service.name}: {service.state}"
            if int(service.reason_code) > 0:
                summary += f" {service.reason_code}: {service.reason_str}"
            yield Result(
                state=_match_service_against_params(params, service),
                summary=summary,
            )


def _match_service_against_params(params: Mapping[str, Any], service: CUCMService) -> State:
    """
    This function searches params for the first rule that matches the state and the start_type.
    None is treated as a wildcard. If no match is found, the function defaults.
    """
    for t_state, mon_state in params.get("states", [("Started", 0)]):
        if _wildcard(t_state, service.state):
            return State(mon_state)
    return State(params.get("else", 2))


def _wildcard(value, reference):
    return value is None or value == reference


def check_cisco_ucm_services(
    item: str,
    params: Mapping[str, Any],
    section: Section,
) -> Generator[Result, None, None]:
    results = list(check_cisco_ucm_services_single(item, params, section))
    if results:
        yield from results
    else:
        yield Result(state=State(params.get("else", 2)), summary="service not found")


def cluster_check_cisco_ucm_services(
    item: str,
    params: Mapping[str, Any],
    section: Mapping[str, Section | None],
) -> CheckResult:
    # A service may appear more than once (due to clusters).
    # First make a list of all matching entries with their
    # states
    found = []
    for node, node_section in section.items():
        if node_section is None:
            continue
        results = list(check_cisco_ucm_services_single(item, params, node_section))
        if results:
            found.append((node, results[0]))

    if not found:
        yield Result(state=State(params.get("else", 2)), summary="service not found")
        return

    # We take the best found state (necessary for clusters)
    best_state = State.best(*(result.state for _node, result in found))
    best_running_on, best_result = [(n, r) for n, r in found if r.state == best_state][-1]

    yield best_result
    if best_running_on and best_state != State.CRIT:
        yield Result(state=best_state, summary="Running on: %s" % best_running_on)


check_plugin_services = CheckPlugin(
    name="cisco_ucm_services",
    service_name="Service %s",
    discovery_ruleset_type=RuleSetType.ALL,
    discovery_ruleset_name="inventory_cisco_ucm_services_rules",
    discovery_function=discovery_cisco_ucm_services,
    discovery_default_parameters=CISCO_UCM_SERVICES_DISCOVERY_DEFAULT_PARAMETERS,
    check_ruleset_name="cisco_ucm",
    check_default_parameters=CISCO_UCM_SERVICES_CHECK_DEFAULT_PARAMETERS,
    check_function=check_cisco_ucm_services,
    cluster_check_function=cluster_check_cisco_ucm_services,
)


def discovery_cisco_ucm_services_summary(section: Section) -> DiscoveryResult:
    if section:
        yield Service()


def check_cisco_ucm_services_summary(params: Mapping[str, Any], section: Section) -> CheckResult:
    blacklist = params.get("ignored", [])
    stoplist = []
    num_blacklist = 0
    num = 0

    for service in section:
        if service.state.lower() == "started":
            num += 1
        if service.state.lower() == "stopped":
            if any(re.match(srv, service.name) for srv in blacklist):
                num_blacklist += 1
            else:
                stoplist.append(service.name)

    yield Result(
        state=State.OK,
        summary=f"Started services: {num}",
        details=f"Started services: {num}\nServices found in total: {len(section)}",
    )

    yield Result(
        state=State(params.get("state_if_stopped", 0)) if stoplist else State.OK,
        summary=f"Stopped services: {len(stoplist)}",
        details=("Stopped services: %s" % ", ".join(stoplist)) if stoplist else None,
    )

    if num_blacklist:
        yield Result(state=State.OK, notice=f"Stopped but ignored: {num_blacklist}")


check_plugin_cisco_ucm_services_summary = CheckPlugin(
    name="cisco_ucm_services_summary",
    sections=["cisco_ucm_services"],
    service_name="Service Summary",
    discovery_function=discovery_cisco_ucm_services_summary,
    check_function=check_cisco_ucm_services_summary,
    check_default_parameters=CISCO_UCM_SERVICES_SUMMARY_DEFAULT_PARAMETERS,
    check_ruleset_name="cisco_ucm_services_summary",
)
