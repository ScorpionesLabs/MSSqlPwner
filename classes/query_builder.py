########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.3.1'
__email__ = ['El3ct71k@gmail.com']

########################################################

import utilities
from impacket import LOG
from typing import Literal
from playbooks import Queries
from classes.base_sql_client import BaseSQLClient


class QueryBuilder(BaseSQLClient):
    def __init__(self, server_address, args_options):
        super().__init__(server_address, args_options)

    def add_rev2self_query(self, chain_id: str, query: str, template: str) -> None:
        """
        This function is responsible to add a command to the rev2self queue.
        """
        raise NotImplementedError

    def get_server_information(self, chain_id: str) -> dict:
        return self.build_chain(chain_id, _get_server_information())

    def get_trustworthy_db_list(self, chain_id: str) -> dict:
        return self.build_chain(chain_id, _get_trustworthy_db_list())

    def get_impersonation_list(self, chain_id: str, user_type: Literal['server', 'database']) -> dict:
        return self.build_chain(chain_id, _get_impersonation_list(user_type))

    def get_user_roles(self, chain_id: str, user_type: Literal['server', 'database']) -> dict:
        return self.build_chain(chain_id, _get_user_roles(user_type))

    def get_database_list(self, chain_id: str) -> dict:
        return self.build_chain(chain_id, _get_database_list())

    def get_user_list(self, chain_id: str, user_type: str) -> dict:
        return self.build_chain(chain_id, _get_user_list(user_type))

    def retrieve_linked_server_list(self, chain_id: str) -> dict:
        return self.build_chain(chain_id, _retrieve_linked_server_list())

    def is_operation_exists(self, chain_id: str, operation_type: Literal['procedure', 'function'],
                            operation_name: str) -> bool:
        if operation_type == 'procedure':
            is_exists_query = _is_procedure_exists(operation_name)
        else:
            is_exists_query = _is_function_exists(operation_name)

        is_exists = self.build_chain(chain_id, is_exists_query)
        if not is_exists['is_success']:
            LOG.error(f"Failed to check if {operation_name} exists")
            return False

        return True if is_exists['results'][0]['status'] == 'True' else True

    def create_operation(self, chain_id: str, operation_type: Literal['procedure', 'function'], asm_name: str,
                         operation_name: str, args: str, db_user: str = None, **kwargs) -> bool:

        if self.is_operation_exists(chain_id, operation_type, operation_name):
            return True

        if operation_type == 'procedure':
            add_operation_query = _create_procedure(asm_name, operation_name, args)
        else:
            add_operation_query = _create_function(db_user, operation_name, asm_name, kwargs['namespace'],
                                                   kwargs['class_name'], args)

        add_operation = self.build_chain(chain_id, add_operation_query, method="exec_at",
                                         indicates_success=['already an object named'])
        if not add_operation['is_success']:
            return False

        if operation_type == 'procedure':
            self.add_rev2self_query(chain_id, _drop_procedure(operation_name),
                                    template=add_operation['template'])
        else:
            self.add_rev2self_query(chain_id, _drop_function(operation_name),
                                    template=add_operation['template'])
        return True

    def execute_operation(self, chain_id, operation_type: str, operation_name: str, command: str, wait: bool = True,
                          db_user: str = None) -> dict:
        if operation_type not in ['procedure', 'function']:
            raise ValueError("Operation type must be 'procedure' or 'function'")
        if operation_type == 'procedure':
            execute_operation = _execute_procedure(operation_name, command)
            return self.build_chain(chain_id, execute_operation, method="exec_at", wait=wait)
        else:
            query = utilities.format_strings(Queries.EXECUTE_FUNCTION, db_user=db_user, function_name=operation_name,
                                             command=command)
            return self.build_chain(chain_id, query, method="OpenQuery", wait=wait)

    def set_server_options(self, chain_id: str, link_name: str, feature: str, status: Literal['true', 'false']) -> bool:
        """
            This function is responsible to set the server options.
        """
        set_server_option = self.build_chain(chain_id, _set_server_options(link_name, feature, status),
                                             method="exec_at")
        if set_server_option['is_success']:
            rev2sef_status = 'true' if status == 'false' else 'false'
            self.add_rev2self_query(chain_id, _set_server_options(link_name, feature, rev2sef_status),
                                    template=set_server_option['template'])
        return set_server_option['is_success']

    def is_procedure_accessible(self, chain_id: str, procedure_name: str) -> bool:
        """
        This function is responsible to check if a procedure is accessible.
        """
        is_procedure_accessible = self.build_chain(chain_id, _is_procedure_accessible(procedure_name))

        if not is_procedure_accessible['is_success']:
            return False
        return True if is_procedure_accessible['results'][0]['is_accessible'] == 'True' else False

    def get_procedure_status(self, chain_id: str, procedure_name: str) -> bool:
        is_enabled = self.build_chain(chain_id, _is_procedure_enabled(procedure_name))

        if not is_enabled['is_success']:
            LOG.error(f"Cant fetch is_{procedure_name}_enabled status")
            return False

        if not is_enabled['results']:
            LOG.error(f"Procedure {procedure_name} not found")
            return False
        return is_enabled['results'][0][f'is_{procedure_name}_enabled'] == 'True'

    def reconfigure_procedure(self, chain_id: str, procedure: str, required_status: bool) -> bool:
        """
        This function is responsible to enable a procedure on the server.
        """

        if self.get_procedure_status(chain_id, procedure) == str(required_status):
            LOG.info(f"{procedure} is already {required_status}")
            return True

        status = 1 if required_status else 0
        rev2self_status = 0 if required_status else 1
        LOG.info(f"Reconfiguring {procedure}")
        reconfigure_procedure = self.build_chain(chain_id, _reconfigure_procedure(procedure, status),
                                                 method="exec_at")
        if not reconfigure_procedure['is_success']:
            LOG.warning(f"Failed to enable {procedure}")
            return False

        self.add_rev2self_query(chain_id, _reconfigure_procedure(procedure, rev2self_status),
                                template=reconfigure_procedure['template'])
        return True

    def is_assembly_exists(self, chain_id: str, asm_name: str) -> bool:
        is_asm_exists = self.build_chain(chain_id, _is_assembly_exists(asm_name))
        if not is_asm_exists['is_success']:
            LOG.error(f"Failed to check if {asm_name} exists")
            return False
        return True if is_asm_exists['results'][0]['status'] == 'True' else False

    def is_custom_assembly_trusted(self, chain_id: str, asm_file_location: str) -> bool:
        is_asm_trusted = self.build_chain(chain_id, _is_custom_asm_trusted(asm_file_location))
        if not is_asm_trusted['is_success']:
            LOG.error(f"Failed to check if {asm_file_location} is trusted")
            return False
        return True if is_asm_trusted['results'][0]['status'] == 'True' else False

    def trust_custom_asm(self, chain_id: str, asm_file_location: str) -> bool:
        if self.is_custom_assembly_trusted(chain_id, asm_file_location):
            LOG.info(f"{asm_file_location} is already trusted")
            return True

        trust_asm = self.build_chain(chain_id, _trust_custom_asm(asm_file_location), method="exec_at")
        if not trust_asm['is_success']:
            LOG.error(f"Failed to trust {asm_file_location} custom assembly")
            return False

        LOG.info(f"Trusting {asm_file_location} custom assembly")
        self.add_rev2self_query(chain_id, _untrust_custom_asm(asm_file_location), template=trust_asm['template'])
        return True

    def add_custom_asm(self, chain_id: str, asm_name: str, asm_file_location: str) -> bool:

        if not self.trust_custom_asm(chain_id, asm_file_location):
            LOG.error(f"Failed to trust {asm_file_location} custom assembly")
            return False

        add_custom_asm = self.build_chain(chain_id, _add_custom_assembly(asm_name, asm_file_location),
                                          method="exec_at", indicates_success=['already exists in database',
                                                                               'is already registered'])
        if not add_custom_asm['is_success']:
            LOG.error(f"Failed to add custom assembly")
            return False
        self.add_rev2self_query(chain_id, _drop_custom_asm(asm_name), template=add_custom_asm['template'])
        LOG.info(f"Added {asm_name} custom assembly")
        return True

    def configure_query_with_defaults(self, chain_id: str, query: str) -> str:
        """
        this function is responsible to add the default operations to a query
        """
        for operation_type, operation_value in self.state['servers_info'][chain_id]['walkthrough'][::-1]:
            if operation_type in ['server', 'database']:
                query = _impersonate_as(operation_type, operation_value, query)
        return query


def _get_server_information() -> str:
    """
    This function is responsible to get the server information.
    """
    return Queries.SERVER_INFORMATION


def _get_trustworthy_db_list() -> str:
    """
    This function is responsible to get the trustworthy database list.
    """
    return Queries.TRUSTWORTHY_DB_LIST


def _get_impersonation_list(user_type: Literal['server', 'database']) -> str:
    if user_type == 'server':
        return Queries.CAN_IMPERSONATE_AS_SERVER_PRINCIPAL
    return Queries.CAN_IMPERSONATE_AS_DATABASE_PRINCIPAL


def _get_user_roles(user_type: Literal['server', 'database']) -> str:
    if user_type == 'server':
        return Queries.GET_USER_SERVER_ROLES
    return Queries.GET_USER_DATABASE_ROLES


def _get_database_list() -> str:
    """
    This function is responsible to get the database list.
    """
    return Queries.DATABASE_LIST


def _get_user_list(user_type: str) -> str:
    if user_type not in ['server', 'database']:
        raise ValueError("User type must be 'server' or 'database'")
    if user_type == 'server':
        return Queries.SERVER_USER_LIST
    return Queries.DB_USER_LIST


def _retrieve_linked_server_list() -> str:
    """
    This function is responsible to retrieve the linked server list.
    """
    return Queries.LINKED_SERVER_LIST


def _impersonate_as(user_type: Literal['server', 'database'], user: str, query: str) -> str:
    if user_type == 'server':
        impersonation_query = utilities.format_strings(Queries.IMPERSONATE_AS_SERVER_PRINCIPAL, username=user)
    else:
        impersonation_query = utilities.format_strings(Queries.IMPERSONATE_AS_DATABASE_PRINCIPAL, username=user)
    return utilities.replace_strings(impersonation_query, {"[QUERY]": query})


def _build_openquery(linked_server: str, query: str) -> str:
    """
    This function is responsible to embed a query within OpenQuery.
    OpenQuery executes a specified pass-through query on the specified linked server
    """
    return utilities.format_strings(Queries.OPENQUERY, linked_server=linked_server, query=query)


def _build_exec_at(linked_server: str, query: str) -> str:
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
    method_func = _build_exec_at if method == "exec_at" else _build_openquery
    return method_func(link, query)


def _execute_procedure(procedure_name: str, command: str) -> str:
    if procedure_name == 'sp_oacreate':
        return utilities.format_strings(Queries.SP_OAMETHOD, command=command)
    else:
        return utilities.format_strings(Queries.EXECUTE_PROCEDURE, procedure=procedure_name, command=command)


def _set_server_options(link_name: str, feature: str, status: str) -> str:
    if status not in ['true', 'false']:
        raise ValueError("Status must be 'true' or 'false'")
    return utilities.format_strings(Queries.SET_SERVER_OPTION, link_name=link_name, feature=feature, status=status)


def _is_procedure_enabled(procedure_name: str) -> str:
    custom_names = {
        "sp_oacreate": "Ole Automation Procedures"
    }
    procedure_name = procedure_name if procedure_name not in custom_names.keys() else custom_names[procedure_name]
    return utilities.format_strings(Queries.IS_PROCEDURE_ENABLED, procedure=procedure_name)


def _reconfigure_procedure(procedure_name: str, status: int) -> str:
    custom_names = {
        "sp_oacreate": "Ole Automation Procedures"
    }
    procedure_name = procedure_name if procedure_name not in custom_names.keys() else custom_names[procedure_name]
    return utilities.format_strings(Queries.RECONFIGURE_PROCEDURE, procedure=procedure_name, status=status)


def _is_assembly_exists(assembly_name: str) -> str:
    return utilities.format_strings(Queries.IS_ASSEMBLY_EXISTS, asm_name=assembly_name)


def _add_custom_assembly(asm_name: str, asm_file_location: str) -> str:
    custom_asm_hex = utilities.hexlify_file(asm_file_location)
    return utilities.format_strings(Queries.ADD_CUSTOM_ASM, custom_asm=custom_asm_hex, asm_name=asm_name)


def _is_procedure_exists(procedure_name: str) -> str:
    return utilities.format_strings(Queries.IS_PROCEDURE_EXISTS, procedure_name=procedure_name)


def _create_procedure(asm_name: str, procedure_name: str, args: str) -> str:
    return utilities.format_strings(Queries.CREATE_PROCEDURE, asm_name=asm_name,
                                    procedure_name=procedure_name, args=args)


def _create_function(db_user: str, function_name: str, asm_name: str, namespace: str, class_name: str, args: str):
    return utilities.format_strings(Queries.CREATE_FUNCTION, db_user=db_user, function_name=function_name,
                                    asm_name=asm_name, namespace=namespace, class_name=class_name, args=args)


def _is_function_exists(function_name: str) -> str:
    return utilities.format_strings(Queries.IS_FUNCTION_EXISTS, function_name=function_name)


def _is_custom_asm_trusted(asm_file_location: str) -> str:
    my_hash = utilities.calculate_sha512_hash(asm_file_location)
    return utilities.format_strings(Queries.IS_CUSTOM_ASM_TRUSTED, my_hash=my_hash)


def _trust_custom_asm(asm_file_location: str) -> str:
    my_hash = utilities.calculate_sha512_hash(asm_file_location)
    return utilities.format_strings(Queries.TRUST_CUSTOM_ASM, my_hash=my_hash)


def _untrust_custom_asm(asm_file_location: str) -> str:
    my_hash = utilities.calculate_sha512_hash(asm_file_location)
    return utilities.format_strings(Queries.UNTRUST_CUSTOM_ASM, my_hash=my_hash)


def _drop_procedure(procedure_name: str) -> str:
    return utilities.format_strings(Queries.DROP_PROCEDURE, procedure_name=procedure_name)


def _drop_custom_asm(asm_name: str) -> str:
    return utilities.format_strings(Queries.DROP_CUSTOM_ASM, asm_name=asm_name)


def _drop_function(function_name: str) -> str:
    return utilities.format_strings(Queries.DROP_FUNCTION, function_name=function_name)


def ldap_query(hostname: str, port: int) -> str:
    return utilities.format_strings(Queries.LDAP_QUERY, hostname=hostname, port=port)


def _is_procedure_accessible(procedure_name: str) -> str:
    return utilities.format_strings(Queries.IS_PROCEDURE_ACCESSIBLE, procedure_name=procedure_name)