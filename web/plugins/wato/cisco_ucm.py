#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.


import cmk.gui.watolib as watolib
from cmk.gui.i18n import _
from cmk.gui.plugins.wato import (
    HostRulespec,
    IndividualOrStoredPassword,
    rulespec_registry,
)
from cmk.gui.plugins.wato.datasource_programs import RulespecGroupDatasourceProgramsApps
from cmk.gui.plugins.wato import (
    CheckParameterRulespecWithItem,
    rulespec_registry,
    RulespecGroupCheckParametersApplications,
    RulespecGroupCheckParametersDiscovery,
    HostRulespec,
    UserIconOrAction,
)
from cmk.gui.valuespec import (
    Alternative,
    Dictionary,
    DropdownChoice,
    FixedValue,
    Integer,
    ListOf,
    ListOfStrings,
    MonitoringState,
    TextAscii,
    Tuple,
)


def _factory_default_special_agents_cisco_ucm():
    # No default, do not use setting if no rule matches
    return watolib.Rulespec.FACTORY_DEFAULT_UNUSED


def _valuespec_special_agents_cisco_ucm():
    return Dictionary(
        title=_("Cisco UCM Services"),
        help=_(
            "This rule allows monitoring of services on Unified Communication Manager"
            " via the Control Centere Services API (SOAP). "
            "You can configure your connection settings here.",),
        elements=[
            ("user", TextAscii(
                title=_("API User name"),
                allow_empty=False,
            )),
            ("secret", IndividualOrStoredPassword(
                title=_("API secret"),
                allow_empty=False,
            )),
            ("tcp_port",
             Integer(
                 title=_("TCP Port number"),
                 help=_("Port number for HTTPS connection"),
                 default_value=8443,
                 minvalue=1,
                 maxvalue=65535,
             )),
            ("ssl",
             Alternative(
                 title=_("SSL certificate checking"),
                 elements=[
                     FixedValue(False, title=_("Deactivated"), totext=""),
                     FixedValue(True, title=_("Use hostname"), totext=""),
                     TextAscii(
                         title=_("Use other hostname"),
                         help=
                         _("The IP of the other hostname needs to be the same IP as the host address"
                          ))
                 ],
                 default_value=True)),
            ("timeout",
             Integer(
                 title=_("Connect Timeout"),
                 help=_(
                     "The network timeout in seconds when communicating with CUCM or "
                     "to the Check_MK Agent. The default is 60 seconds. Please note that this "
                     "is not a total timeout but is applied to each individual network transation."
                 ),
                 default_value=60,
                 minvalue=1,
                 unit=_("seconds"),
             )),
        ],
        optional_keys=[
            "tcp_port",
            "timeout",
        ],
    )


rulespec_registry.register(
    HostRulespec(
        factory_default=_factory_default_special_agents_cisco_ucm(),
        group=RulespecGroupDatasourceProgramsApps,
        name="special_agents:cisco_ucm",
        valuespec=_valuespec_special_agents_cisco_ucm,
    ))


def _valuespec_inventory_services_rules():
    return Dictionary(
        title=_("Cisco UCM service discovery"),
        elements=[
            ('cisco_ucm_services',
             ListOfStrings(
                 title=_("Services (Regular Expressions)"),
                 help=_('Regular expressions matching the begining of the service name. '
                        'If no name is given then this rule will match all services. The '
                        'match is done on the <i>beginning</i> of the service name. It '
                        'is done <i>case sensitive</i>. You can do a case insensitive match '
                        'by prefixing the regular expression with <tt>(?i)</tt>. Example: '
                        '<tt>(?i).*callmanager</tt> matches all services which contain <tt>CALLMANAGER</tt> '
                        'or <tt>CallManager</tt> or <tt>callmanager</tt> or...'),
                 orientation="horizontal",
             )),
            ('state',
             DropdownChoice(
                 choices=[
                     ('started', _('Started')),
                     ('stopped', _('Stopped')),
                 ],
                 title=_("Create check if service is in state"),
             )),
        ],
        help=_(
            'This rule can be used to configure the inventory of the Cisco UCM services check. '
            'You can configure specific Cisco UCM services to be monitored by the check by '
            'selecting them by name or by current state during the inventory.'),
    )


rulespec_registry.register(
    HostRulespec(
        group=RulespecGroupCheckParametersDiscovery,
        match_type="all",
        name="inventory_cisco_services_ucm_rules",
        valuespec=_valuespec_inventory_services_rules,
    ))


def _item_spec_services():
    return TextAscii(title=_("Name of the service"),
                     allow_empty=False)


def _parameter_valuespec_services():
    return Dictionary(elements=[
        ("additional_servicenames",
         ListOfStrings(
             title=_("Alternative names for the service"),
             help=_("Here you can specify alternative names that the service might have. "
                    "This helps when the exact spelling of the services can changed from "
                    "one version to another."),
         )),
        ("states",
         ListOf(
             Tuple(orientation="horizontal",
                   elements=[
                       DropdownChoice(
                           title=_("Expected state"),
                           default_value="started",
                           choices=[(None, _("ignore the state")), ("started", _("started")),
                                    ("stopped", _("stopped"))],
                       ),
                       MonitoringState(title=_("Resulting state"),),
                   ],
                   default_value=("started", 0)),
             title=_("Services states"),
             help=_("You can specify a separate monitoring state for each possible "
                    "combination of service state. If you do not use "
                    "this parameter, then only started will be assumed to be OK."),
         )),
        ("else",
         MonitoringState(
                 title=_("State if no entry matches"),
                 default_value=2,
         )),
    ],)


rulespec_registry.register(
    CheckParameterRulespecWithItem(
        check_group_name="cisco_ucm_services",
        group=RulespecGroupCheckParametersApplications,
        item_spec=_item_spec_services,
        match_type="dict",
        parameter_valuespec=_parameter_valuespec_services,
        title=lambda: _("Cisco UCM Services"),
    ))
