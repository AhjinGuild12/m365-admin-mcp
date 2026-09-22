"""MCPServer app: stdio-only, exactly the 15-tool allowlist."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from m365_mcp_kernel.errors import SanitizedGraphError
from m365_mcp_kernel.graph_client import GraphClient
from m365_mcp_kernel.server_factory import ToolSpec, create_server, registered_tool_names, run_stdio

from exchange_admin_mcp.allowlist import TOOL_NAMES
from exchange_admin_mcp.exo_client import ExoAdminApiClient
from exchange_admin_mcp.tools import groups, mailboxes, message_trace, org, reports, rooms
from exchange_admin_mcp.tools._common import finalize

_graph_factory: Callable[[], GraphClient] = lambda: GraphClient(env_prefix="EXO")
_exo_factory: Callable[[], ExoAdminApiClient] = lambda: ExoAdminApiClient(env_prefix="EXO")
_cached_graph: GraphClient | None = None
_cached_exo: ExoAdminApiClient | None = None


def get_graph_client() -> GraphClient:
    global _cached_graph
    if _cached_graph is None:
        _cached_graph = _graph_factory()
    return _cached_graph


def get_exo_client() -> ExoAdminApiClient:
    global _cached_exo
    if _cached_exo is None:
        _cached_exo = _exo_factory()
    return _cached_exo


def set_graph_client_factory(factory: Callable[[], GraphClient] | None) -> None:
    """Test hook. Pass None to restore the default factory and drop the cache."""
    global _graph_factory, _cached_graph
    _cached_graph = None
    _graph_factory = factory or (lambda: GraphClient(env_prefix="EXO"))


def set_exo_client_factory(factory: Callable[[], ExoAdminApiClient] | None) -> None:
    """Test hook. Pass None to restore the default factory and drop the cache."""
    global _exo_factory, _cached_exo
    _cached_exo = None
    _exo_factory = factory or (lambda: ExoAdminApiClient(env_prefix="EXO"))


def _invoke(fn: Callable[..., Any], client: Any, **kwargs: Any) -> Any:
    try:
        return finalize(fn(client, **kwargs))
    except SanitizedGraphError:
        raise
    except Exception:
        raise SanitizedGraphError("internal_error", status_class="other") from None


def list_message_traces(
    sender: str | None = None,
    recipient: str | None = None,
    message_id: str | None = None,
    status: str | None = None,
    subject: str | None = None,
    start: str | None = None,
    end: str | None = None,
    top: int | None = None,
) -> dict[str, Any]:
    """Where did a message go? Summaries from Graph v1.0. IP addresses are removed."""
    return _invoke(
        message_trace.list_message_traces,
        get_graph_client(),
        sender=sender,
        recipient=recipient,
        message_id=message_id,
        status=status,
        subject=subject,
        start=start,
        end=end,
        top=top,
    )


def get_message_trace_details(
    trace_id: str, recipient: str, top: int | None = None
) -> dict[str, Any]:
    """Per-recipient processing events for one trace id. The detail data blob is removed."""
    return _invoke(
        message_trace.get_message_trace_details,
        get_graph_client(),
        trace_id=trace_id,
        recipient=recipient,
        top=top,
    )


def list_rooms(top: int | None = None) -> dict[str, Any]:
    """Rooms from Places. This is not calendar availability."""
    return _invoke(rooms.list_rooms, get_graph_client(), top=top)


def list_room_lists(top: int | None = None) -> dict[str, Any]:
    """Room lists from Places."""
    return _invoke(rooms.list_room_lists, get_graph_client(), top=top)


def list_rooms_in_room_list(room_list: str, top: int | None = None) -> dict[str, Any]:
    """Rooms in one room list, by the list's email address."""
    return _invoke(
        rooms.list_rooms_in_room_list, get_graph_client(), room_list=room_list, top=top
    )


def get_room(room_id: str) -> dict[str, Any]:
    """One room by its Places id."""
    return _invoke(rooms.get_room, get_graph_client(), room_id=room_id)


def list_mailbox_usage_report(period: str) -> dict[str, Any]:
    """Mailbox usage detail for D7, D30, D90, or D180. Concealed names stay concealed."""
    return _invoke(reports.list_mailbox_usage_report, get_graph_client(), period=period)


def list_email_activity_report(period: str) -> dict[str, Any]:
    """Email activity by user for D7, D30, D90, or D180. Concealed names stay concealed."""
    return _invoke(reports.list_email_activity_report, get_graph_client(), period=period)


def list_mailboxes(recipient_type: str = "all", top: int | None = None) -> dict[str, Any]:
    """Mailboxes of one recipient type: user, shared, room, equipment, or all."""
    return _invoke(
        mailboxes.list_mailboxes,
        get_exo_client(),
        recipient_type=recipient_type,
        top=top,
    )


def get_mailbox(identity: str, include_delegate_names: bool = False) -> dict[str, Any]:
    """One mailbox, including Send on behalf delegates when the tenant returns them."""
    return _invoke(
        mailboxes.get_mailbox,
        get_exo_client(),
        identity=identity,
        include_delegate_names=include_delegate_names,
    )


def list_mailbox_folder_permissions(
    mailbox: str, folder_path: str = "Calendar", top: int | None = None
) -> dict[str, Any]:
    """Who can see one mailbox folder. The folder defaults to Calendar."""
    return _invoke(
        mailboxes.list_mailbox_folder_permissions,
        get_exo_client(),
        mailbox=mailbox,
        folder_path=folder_path,
        top=top,
    )


def list_distribution_group_members(identity: str, top: int | None = None) -> dict[str, Any]:
    """Members of one distribution group, including a room list."""
    return _invoke(
        groups.list_distribution_group_members,
        get_exo_client(),
        identity=identity,
        top=top,
    )


def list_dynamic_distribution_group_members(
    identity: str, top: int | None = None
) -> dict[str, Any]:
    """Members of one dynamic distribution group."""
    return _invoke(
        groups.list_dynamic_distribution_group_members,
        get_exo_client(),
        identity=identity,
        top=top,
    )


def list_accepted_domains(top: int | None = None) -> dict[str, Any]:
    """Accepted domains for the organization."""
    return _invoke(org.list_accepted_domains, get_exo_client(), top=top)


def get_organization_config() -> dict[str, Any]:
    """MailTips settings from the organization configuration."""
    return _invoke(org.get_organization_config, get_exo_client())


_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("list_message_traces", list_message_traces, list_message_traces.__doc__ or ""),
    ToolSpec(
        "get_message_trace_details",
        get_message_trace_details,
        get_message_trace_details.__doc__ or "",
    ),
    ToolSpec("list_rooms", list_rooms, list_rooms.__doc__ or ""),
    ToolSpec("list_room_lists", list_room_lists, list_room_lists.__doc__ or ""),
    ToolSpec(
        "list_rooms_in_room_list",
        list_rooms_in_room_list,
        list_rooms_in_room_list.__doc__ or "",
    ),
    ToolSpec("get_room", get_room, get_room.__doc__ or ""),
    ToolSpec(
        "list_mailbox_usage_report",
        list_mailbox_usage_report,
        list_mailbox_usage_report.__doc__ or "",
    ),
    ToolSpec(
        "list_email_activity_report",
        list_email_activity_report,
        list_email_activity_report.__doc__ or "",
    ),
    ToolSpec("list_mailboxes", list_mailboxes, list_mailboxes.__doc__ or ""),
    ToolSpec("get_mailbox", get_mailbox, get_mailbox.__doc__ or ""),
    ToolSpec(
        "list_mailbox_folder_permissions",
        list_mailbox_folder_permissions,
        list_mailbox_folder_permissions.__doc__ or "",
    ),
    ToolSpec(
        "list_distribution_group_members",
        list_distribution_group_members,
        list_distribution_group_members.__doc__ or "",
    ),
    ToolSpec(
        "list_dynamic_distribution_group_members",
        list_dynamic_distribution_group_members,
        list_dynamic_distribution_group_members.__doc__ or "",
    ),
    ToolSpec("list_accepted_domains", list_accepted_domains, list_accepted_domains.__doc__ or ""),
    ToolSpec(
        "get_organization_config",
        get_organization_config,
        get_organization_config.__doc__ or "",
    ),
)

mcp = create_server("exchange-admin-ro", _TOOLS, declared_names=TOOL_NAMES)


def advertised_tool_names() -> tuple[str, ...]:
    return registered_tool_names(mcp)


def main() -> None:
    run_stdio(mcp)
