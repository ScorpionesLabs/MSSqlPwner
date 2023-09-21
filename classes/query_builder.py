########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.3.1'
__email__ = ['El3ct71k@gmail.com']
########################################################

import utilities
from typing import Literal
from playbooks import Queries


def get_impersonation_list(user_type: Literal['server', 'database']) -> str:
    if user_type == 'server':
        return Queries.CAN_IMPERSONATE_AS_SERVER_PRINCIPAL
    return Queries.CAN_IMPERSONATE_AS_DATABASE_PRINCIPAL


def get_user_list(user_type: str) -> str:
    if user_type not in ['server', 'database']:
        raise ValueError("User type must be 'server' or 'database'")
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


def execute_procedure(procedure_name: str, command: str) -> str:
    if procedure_name == 'sp_oacreate':
        return utilities.format_strings(Queries.SP_OAMETHOD, command=command)
    else:
        return utilities.format_strings(Queries.EXECUTE_PROCEDURE, procedure=procedure_name, command=command)


def set_server_options(link_name: str, feature: str, status: str) -> str:
    if status not in ['true', 'false']:
        raise ValueError("Status must be 'true' or 'false'")
    return utilities.format_strings(Queries.SET_SERVER_OPTION, link_name=link_name, feature=feature, status=status)


def get_server_information() -> str:
    return Queries.SERVER_INFORMATION


def get_trustworthy_db_list() -> str:
    return Queries.TRUSTWORTHY_DB_LIST


def is_procedure_accessible(procedure_name: str) -> str:
    return utilities.format_strings(Queries.IS_PROCEDURE_ACCESSIBLE, procedure=procedure_name)


def is_procedure_enabled(procedure_name: str) -> str:
    custom_names = {
        "sp_oacreate": "Ole Automation Procedures"
    }
    procedure_name = procedure_name if procedure_name not in custom_names.keys() else custom_names[procedure_name]
    return utilities.format_strings(Queries.IS_PROCEDURE_ENABLED, procedure=procedure_name)


def reconfigure_procedure(procedure_name: str, status: int) -> str:
    custom_names = {
        "sp_oacreate": "Ole Automation Procedures"
    }
    procedure_name = procedure_name if procedure_name not in custom_names.keys() else custom_names[procedure_name]
    return utilities.format_strings(Queries.RECONFIGURE_PROCEDURE, procedure=procedure_name, status=status)


def is_assembly_exists(assembly_name: str) -> str:
    return utilities.format_strings(Queries.IS_ASSEMBLY_EXISTS, asm_name=assembly_name)


def add_custom_assembly(asm_name: str, custom_asm_hex: str) -> str:
    return utilities.format_strings(Queries.ADD_CUSTOM_ASM, custom_asm=custom_asm_hex, asm_name=asm_name)


def is_procedure_exists(procedure_name: str) -> str:
    return utilities.format_strings(Queries.IS_PROCEDURE_EXISTS, procedure_name=procedure_name)


def create_procedure(asm_name: str, procedure_name: str, args: str) -> str:
    return utilities.format_strings(Queries.CREATE_PROCEDURE, asm_name=asm_name,
                                    procedure_name=procedure_name, args=args)


def is_function_exists(function_name: str) -> str:
    return utilities.format_strings(Queries.IS_FUNCTION_EXISTS, function_name=function_name)


def create_function(db_user: str, function_name: str, asm_name: str, namespace: str, class_name: str, args: str):
    return utilities.format_strings(Queries.CREATE_FUNCTION, db_user=db_user, function_name=function_name,
                                    asm_name=asm_name, namespace=namespace, class_name=class_name, arg=args)


def is_app_trusted(asm_file_location: str) -> str:
    my_hash = utilities.calculate_sha512_hash(asm_file_location)
    return utilities.format_strings(Queries.IS_MY_APP_TRUSTED, my_hash=my_hash)


def trust_my_app(asm_file_location: str) -> str:
    my_hash = utilities.calculate_sha512_hash(asm_file_location)
    return utilities.format_strings(Queries.TRUST_MY_APP, my_hash=my_hash)


def untrust_my_app(asm_file_location: str) -> str:
    my_hash = utilities.calculate_sha512_hash(asm_file_location)
    return utilities.format_strings(Queries.UNTRUST_MY_APP, my_hash=my_hash)


def drop_procedure(procedure_name: str) -> str:
    return utilities.format_strings(Queries.DROP_PROCEDURE, procedure_name=procedure_name)


def drop_assembly(asm_name: str) -> str:
    return utilities.format_strings(Queries.DROP_ASSEMBLY, asm_name=asm_name)


def drop_function(function_name: str) -> str:
    return utilities.format_strings(Queries.DROP_FUNCTION, function_name=function_name)


def execute_function(db_user: str, function_name: str, command: str) -> str:
    return utilities.format_strings(Queries.EXECUTE_FUNCTION, db_user=db_user,  function_name=function_name,
                                    command=command)


def ldap_query(hostname: str, port: int) -> str:
    return utilities.format_strings(Queries.LDAP_QUERY, hostname=hostname, port=port)
