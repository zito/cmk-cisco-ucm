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
from cmk.gui.valuespec import (
    Alternative,
    Dictionary,
    FixedValue,
    Integer,
    TextAscii,
)



def _factory_default_special_agents_cisco_ucm_ccs():
    # No default, do not use setting if no rule matches
    return watolib.Rulespec.FACTORY_DEFAULT_UNUSED


def _valuespec_special_agents_cisco_ucm_ccs():
    return Dictionary(
        title=_("Cisco UCM Services via CCS API"),
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
                 help=_("Port number for HTTPS connection to CCS API"),
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
        factory_default=_factory_default_special_agents_cisco_ucm_ccs(),
        group=RulespecGroupDatasourceProgramsApps,
        name="special_agents:cisco_ucm_ccs",
        valuespec=_valuespec_special_agents_cisco_ucm_ccs,
    ))

