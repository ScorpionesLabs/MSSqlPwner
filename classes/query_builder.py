import utilities
from typing import Literal
from playbooks import Queries


def get_impersonation_list(user_type: Literal['server', 'database']) -> str:
    if user_type == 'server':
        return Queries.CAN_IMPERSONATE_AS_SERVER_PRINCIPAL
    return Queries.CAN_IMPERSONATE_AS_DATABASE_PRINCIPAL


def get_user_list(user_type: Literal['server', 'database']) -> str:
    if user_type == 'server':
        return Queries.SERVER_USER_LIST
    return Queries.DB_USER_LIST


def get_user_roles(user_type: Literal['server', 'database']) -> str:
    if user_type == 'server':
        return Queries.GET_USER_SERVER_ROLES
    return Queries.GET_USER_DATABASE_ROLES


def impersonate_as(user_type: Literal['server', 'database'], user: str) -> str:
    if user_type == 'server':
        return utilities.format_strings(Queries.IMPERSONATE_AS_SERVER_PRINCIPAL, username=user)
    return utilities.format_strings(Queries.IMPERSONATE_AS_DATABASE_PRINCIPAL, username=user)


def get_database_list() -> str:
    return Queries.DATABASE_LIST


def get_linked_server_list() -> str:
    return Queries.LINKED_SERVER_LIST


def build_openquery(linked_server: str, query: str) -> str:
    """
    This function is responsible to embed a query within OpenQuery.
    OpenQuery executes a specified pass-through query on the specified linked server
    """
    return utilities.format_strings(Queries.OPENQUERY, linked_server=linked_server, query=query)


def build_exec_at(linked_server: str, query: str) -> str:
    """
    This function is responsible to embed a query within a procedure (That can also contains a query)
    exec executes a command string or character string within a Transact-SQL batch.
    This function uses the "at" argument to refer the query to another linked server.
    """
    return utilities.format_strings(Queries.EXEC_AT, linked_server=linked_server, query=query)


def link_query(link: str, query: str, method: Literal["exec_at", "OpenQuery", "blind_OpenQuery"]) -> str:
    """
    This function is responsible to link a query to a linked server.
    """
    method_func = build_exec_at if method == "exec_at" else build_openquery
    return method_func(link, query)


def execute_procedure(procedure_type: str, command: str) -> str:
    if procedure_type == 'sp_oacreate':
        return utilities.format_strings(Queries.SP_OAMETHOD, command=command)
    else:
        return utilities.format_strings(Queries.PROCEDURE_EXECUTION, procedure=procedure_type, command=command)


def set_server_options(link_name: str, feature: str, status: Literal['true', 'false']) -> str:
    return utilities.format_strings(Queries.SET_SERVER_OPTION, link_name=link_name, feature=feature, status=status)