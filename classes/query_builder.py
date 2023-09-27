########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.3.2'
__email__ = ['El3ct71k@gmail.com']
########################################################

import utilities
from abc import ABC
from impacket import LOG
from playbooks import Queries
from typing import Literal, Union
from classes.base_sql_client import BaseSQLClient


class QueryBuilder(BaseSQLClient, ABC):
    def __init__(self, server_address, args_options):
        super().__init__(server_address, args_options)
        self.high_privileged_server_roles = ['sysadmin']
        self.high_privileged_database_roles = ['db_owner']

    def build_chain(self, chain_id: str, query: str, method: str = "OpenQuery",
                    decode_results: bool = True, print_results: bool = False, adsi_provider: str = None,
                    wait: bool = True, indicates_success: list = None,
                    used_methods: set = None) -> Union[dict, utilities.CustomThread]:
        """
         This function is responsible to build the query chain for the given query and method.
        """
        method_list = ['OpenQuery', 'exec_at']
        if method not in method_list:
            raise Exception(f"Method {method} not supported. Supported methods: {method_list}")
        ret_val = {}
        if not used_methods:
            used_methods = set()
        if not indicates_success:
            indicates_success = []
        query_tpl = "[PAYLOAD]"
        if adsi_provider:
            query_tpl = Queries.link_query(adsi_provider, query_tpl, method)
        for query_tpl in self.generate_query(chain_id, query_tpl, method):
            chained_query = utilities.replace_strings(query_tpl, {"[PAYLOAD]": query})
            ret_val = self.custom_sql_query(chained_query, print_results=print_results, decode_results=decode_results,
                                            wait=wait, indicates_success=indicates_success)
            ret_val['template'] = query_tpl
            if ret_val['is_success']:
                return ret_val
            return ret_val
        used_methods.add(method)
        for new_method in method_list:
            if new_method == method or new_method in used_methods:
                continue
            LOG.info(f"Trying {new_method} method")
            return self.build_chain(chain_id, query, new_method, decode_results, print_results, adsi_provider, wait,
                                    indicates_success, used_methods)
        return ret_val

    def add_rev2self_query(self, chain_id: str, query: str, template: str) -> None:
        """
        This function is responsible to add a command to the rev2self queue.
        """
        raise NotImplementedError

    def get_server_information(self, chain_id: str) -> dict:
        return self.build_chain(chain_id, Queries.get_server_information())

    def get_trustworthy_db_list(self, chain_id: str) -> dict:
        return self.build_chain(chain_id, Queries.get_trustworthy_db_list())

    def get_impersonation_list(self, chain_id: str, user_type: Literal['server', 'database']) -> dict:
        return self.build_chain(chain_id, Queries.get_impersonation_list(user_type))

    def get_user_roles(self, chain_id: str, user_type: Literal['server', 'database']) -> dict:
        return self.build_chain(chain_id, Queries.get_user_roles(user_type))

    def get_database_list(self, chain_id: str) -> dict:
        return self.build_chain(chain_id, Queries.get_database_list())

    def get_user_list(self, chain_id: str, user_type: str) -> dict:
        return self.build_chain(chain_id, Queries.get_user_list(user_type))

    def retrieve_linked_server_list(self, chain_id: str) -> dict:
        return self.build_chain(chain_id, Queries.retrieve_linked_server_list())

    def is_operation_exists(self, chain_id: str, operation_type: Literal['procedure', 'function'],
                            operation_name: str) -> bool:
        if operation_type == 'procedure':
            is_exists_query = Queries.is_procedure_exists(operation_name)
        else:
            is_exists_query = Queries.is_function_exists(operation_name)

        is_exists = self.build_chain(chain_id, is_exists_query)
        if not is_exists['is_success']:
            LOG.error(f"Failed to check if {operation_name} exists")
            return False

        return True if is_exists['results'][0]['status'] == 'True' else False

    def create_operation(self, chain_id: str, operation_type: Literal['procedure', 'function'], asm_name: str,
                         operation_name: str, args: str, db_user: str = None, **kwargs) -> bool:

        if self.is_operation_exists(chain_id, operation_type, operation_name):
            return True

        if operation_type == 'procedure':
            add_operation_query = Queries.create_procedure(asm_name, operation_name, args)
        else:
            add_operation_query = Queries.create_function(db_user, operation_name, asm_name, kwargs['namespace'],
                                                          kwargs['class_name'], args)

        add_operation = self.build_chain(chain_id, add_operation_query, method="exec_at",
                                         indicates_success=['already an object named'])
        if not add_operation['is_success']:
            return False

        if operation_type == 'procedure':
            self.add_rev2self_query(chain_id, Queries.drop_procedure(operation_name),
                                    template=add_operation['template'])
        else:
            self.add_rev2self_query(chain_id, Queries.drop_function(operation_name),
                                    template=add_operation['template'])
        return True

    def execute_operation(self, chain_id, operation_type: str, operation_name: str, command: str, wait: bool = True,
                          db_user: str = None) -> dict:
        if operation_type not in ['procedure', 'function']:
            raise ValueError("Operation type must be 'procedure' or 'function'")
        if operation_type == 'procedure':
            execute_procedure = Queries.execute_procedure(operation_name, command)
            return self.build_chain(chain_id, execute_procedure, method="exec_at", wait=wait)
        else:
            execute_function = Queries.execute_function(operation_name, command, db_user)
            return self.build_chain(chain_id, execute_function, method="OpenQuery", wait=wait)

    def set_server_options(self, chain_id: str, link_name: str, feature: str, status: Literal['true', 'false']) -> bool:
        """
            This function is responsible to set the server options.
        """
        set_server_option = self.build_chain(chain_id, Queries.set_server_options(link_name, feature, status),
                                             method="exec_at")
        if set_server_option['is_success']:
            LOG.info(f"{feature} is set to {status} on {link_name}")
            rev2sef_status = 'true' if status == 'false' else 'false'
            self.add_rev2self_query(chain_id, Queries.set_server_options(link_name, feature, rev2sef_status),
                                    template=set_server_option['template'])
        return set_server_option['is_success']

    def is_procedure_accessible(self, chain_id: str, procedure_name: str) -> bool:
        """
        This function is responsible to check if a procedure is accessible.
        """
        if not self.is_operation_exists(chain_id, 'procedure', procedure_name):
            LOG.error(f"Procedure {procedure_name} not found")
            return True
        is_procedure_accessible = self.build_chain(chain_id, Queries.is_procedure_accessible(procedure_name))

        if not is_procedure_accessible['is_success']:
            return False
        return True if is_procedure_accessible['results'][0]['is_accessible'] == 'True' else False

    def get_procedure_status(self, chain_id: str, procedure_name: str) -> bool:
        is_enabled = self.build_chain(chain_id, Queries.is_procedure_enabled(procedure_name))

        if not is_enabled['is_success']:
            LOG.error(f"Cant fetch is_{procedure_name}_enabled status")
            return False

        if not is_enabled['results']:
            LOG.error(f"Procedure {procedure_name} not found")
            return False
        return is_enabled['results'][0]['status'] == 'True'

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
        reconfigure_procedure = self.build_chain(chain_id, Queries.reconfigure_procedure(procedure, status),
                                                 method="exec_at")
        if not reconfigure_procedure['is_success']:
            LOG.warning(f"Failed to enable {procedure}")
            return False

        self.add_rev2self_query(chain_id, Queries.reconfigure_procedure(procedure, rev2self_status),
                                template=reconfigure_procedure['template'])
        return True

    def is_assembly_exists(self, chain_id: str, asm_name: str) -> bool:
        is_asm_exists = self.build_chain(chain_id, Queries.is_assembly_exists(asm_name))
        if not is_asm_exists['is_success']:
            LOG.error(f"Failed to check if {asm_name} exists")
            return False
        return True if is_asm_exists['results'][0]['status'] == 'True' else False

    def is_custom_assembly_trusted(self, chain_id: str, asm_file_location: str) -> bool:
        is_asm_trusted = self.build_chain(chain_id, Queries.is_custom_asm_trusted(asm_file_location))
        if not is_asm_trusted['is_success']:
            LOG.error(f"Failed to check if {asm_file_location} is trusted")
            return False
        return True if is_asm_trusted['results'][0]['status'] == 'True' else False

    def trust_custom_asm(self, chain_id: str, asm_file_location: str) -> bool:
        if self.is_custom_assembly_trusted(chain_id, asm_file_location):
            LOG.info(f"{asm_file_location} is already trusted")
            return True

        trust_asm = self.build_chain(chain_id, Queries.trust_custom_asm(asm_file_location), method="exec_at")
        if not trust_asm['is_success']:
            LOG.error(f"Failed to trust {asm_file_location} custom assembly")
            return False

        LOG.info(f"Trusting {asm_file_location} custom assembly")
        self.add_rev2self_query(chain_id, Queries.untrust_custom_asm(asm_file_location), template=trust_asm['template'])
        return True

    def add_custom_asm(self, chain_id: str, asm_name: str, asm_file_location: str) -> bool:

        if not self.trust_custom_asm(chain_id, asm_file_location):
            LOG.error(f"Failed to trust {asm_file_location} custom assembly")
            return False

        add_custom_asm = self.build_chain(chain_id, Queries.add_custom_assembly(asm_name, asm_file_location),
                                          method="exec_at", indicates_success=['already exists in database',
                                                                               'is already registered'])
        if not add_custom_asm['is_success']:
            LOG.error(f"Failed to add custom assembly")
            return False
        self.add_rev2self_query(chain_id, Queries.drop_custom_asm(asm_name), template=add_custom_asm['template'])
        LOG.info(f"Added {asm_name} custom assembly")
        return True

    def configure_query_with_defaults(self, chain_id: str, query: str) -> str:
        """
        this function is responsible to add the default operations to a query
        """
        server_info = self.get_server_info(chain_id)

        for operation_type, operation_value in server_info['walkthrough'][::-1]:
            if operation_type in ['server', 'database']:
                query = Queries.impersonate_as(operation_type, operation_value, query)
        return query

