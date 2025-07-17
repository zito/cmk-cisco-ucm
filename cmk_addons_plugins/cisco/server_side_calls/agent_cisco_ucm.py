#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
"""server side component to create the special agent call"""

from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel

from cmk.server_side_calls.v1 import (
    HostConfig,
    Secret,
    SpecialAgentCommand,
    SpecialAgentConfig,
)


class Params(BaseModel):
    """params validator"""
    user: str
    secret: Secret
    tcp_port: int | None = None
    ssl: (
        tuple[Literal["deactivated"], None]
        | tuple[Literal["hostname"], None]
        | tuple[Literal["custom_hostname"], str]
    )
    timeout: int | None = None


def commands_function(params: Params, host_config: HostConfig) -> Iterable[SpecialAgentCommand]:
    command_arguments: list[str | Secret] = []
    if params.tcp_port is not None: 
        command_arguments += ["-p", str(params.tcp_port)] 
    command_arguments += ["-u", params.user]
    command_arguments += [params.secret.unsafe("-s=%s")]
    if params.timeout:
        command_arguments += ["-t", str(params.timeout)]
    if params.ssl[0] == "deactivated":
        command_arguments += ["--no-cert-check"]
        host = host_config.name or primary_ip_config.address
    elif params.ssl[0] == "hostname":
        host = host_config.name
    else:
        host = params.ssl[1]
    command_arguments.append(host)
    yield SpecialAgentCommand(command_arguments=command_arguments)


special_agent_cisco_ucm = SpecialAgentConfig(
    name="cisco_ucm",
    parameter_parser=Params.model_validate,
    commands_function=commands_function,
)
