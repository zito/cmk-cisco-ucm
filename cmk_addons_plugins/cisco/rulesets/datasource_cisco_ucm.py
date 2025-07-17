#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
"""rule for assinging the special agent to host objects"""

# License: GNU General Public License v2

from typing import Literal

from cmk.rulesets.v1 import Title, Help
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    DictElement,
    Dictionary,
    FixedValue,
    Integer,
    migrate_to_password,
    Password,
    String,
    validators,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def parameter_form() -> Dictionary:
    return Dictionary(
        title=Title("Cisco UCM Services"),
        help_text=Help(
            "This rule allows monitoring of services on Unified Communication Manager"
            " via the Control Center Services API (SOAP). "
            "You can configure your connection settings here.",
        ),
        elements={
            "user": DictElement(
                parameter_form=String(
                    title=Title("API User name"),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
                required=True,
            ),
            "secret": DictElement(
                parameter_form=Password(
                    title=Title("API secret"),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                    migrate=migrate_to_password,
                ),
                required=True,
            ),
            "tcp_port": DictElement(
                parameter_form=Integer(
                    title=Title("TCP Port number"),
                    help_text=Help("Port number for HTTPS connection"),
                    prefill=DefaultValue(8443),
                    custom_validate=(validators.NetworkPort(),),
                ),
                required=False,
            ),
            "ssl": DictElement(
                parameter_form=CascadingSingleChoice(
                    title=Title("SSL certificate checking"),
                    elements=[
                        CascadingSingleChoiceElement(
                            name="deactivated",
                            title=Title("Deactivated"),
                            parameter_form=FixedValue(value=None),
                        ),
                        CascadingSingleChoiceElement(
                            name="hostname",
                            title=Title("Use host name"),
                            parameter_form=FixedValue(value=None),
                        ),
                        CascadingSingleChoiceElement(
                            name="custom_hostname",
                            title=Title("Use other host name"),
                            parameter_form=String(
                                help_text=Help(
                                    "Use a custom name for the SSL certificate validation"
                                ),
                                macro_support=True,
                            ),
                        ),
                    ],
                    prefill=DefaultValue("hostname"),
                    migrate=_migrate_ssl,
                ),
                required=True,
            ),
            "timeout": DictElement(
                parameter_form=Integer(
                    title=Title("Connect timeout"),
                    help_text=Help(
                        "The network timeout in seconds when communicating with CUCM or "
                        "to the Check_MK Agent. The default is 60 seconds. Please note that this "
                        "is not a total timeout but is applied to each individual network transation."
                    ),
                    prefill=DefaultValue(60),
                    custom_validate=(validators.NumberInRange(min_value=1),),
                    unit_symbol="seconds",
                ),
                required=False,
            ),
        },
    )


def _migrate_ssl(
    value: object,
) -> (
    tuple[Literal["deactivated"], None]
    | tuple[Literal["hostname"], None]
    | tuple[Literal["custom_hostname"], str]
):
    match value:
        case tuple():
            return value
        case False:
            return ("deactivated", None)
        case True:
            return ("hostname", None)
        case str():
            return ("custom_hostname", value)
        case _:
            raise TypeError(value)



rule_spec_cisco_ucm_datasource_programs = SpecialAgent(
    name="cisco_ucm",
    title=Title("Cisco UCM"),
    topic=Topic.APPLICATIONS,
    parameter_form=parameter_form,
)
