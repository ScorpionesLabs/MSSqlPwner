import os
import re
import json
import string
import random
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


def generate_string(size=6, chars=string.ascii_uppercase + string.ascii_lowercase) -> str:
    """
    This function is responsible to generate a random string.
    """
    return ''.join(random.choice(chars) for _ in range(size))


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
    custom_names = {
        "sp_oacreate": "Ole Automation Procedures"
    }

    if procedure_name in custom_names.keys():
        return custom_names[procedure_name]
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


def receive_answer(question: str, possible_answers: list, true_result_answer: str) -> bool:
    """
    This function is responsible to receive an answer from the user.
    """
    while True:
        answer = input(f"{question} ({'/'.join(possible_answers)}): ").lower()
        if answer in possible_answers:
            return answer == true_result_answer
        LOG.error(f"Invalid answer, only the following answers are allowed: {','.join(possible_answers)}")


def print_state(state: dict) -> None:
    """
    This function is responsible to print the last enumeration from the stored state.
    """
    LOG.info("Linkable servers:")
    translation = json.load(open(os.path.join("./", "playbooks", "translation.json")))
    for _, server_info in state['servers_info'].items():
        for translation_key, translation_value in translation.items():
            if translation_key in server_info.keys():
                val = server_info[translation_key]
                if not val:
                    continue
                if isinstance(val, list):
                    val = ', '.join(val)

                LOG.info(f"{translation_value}: {str(val).strip()}")
        LOG.info("-" * 50)


def is_string_in_lists(current_groups: list, privileged_groups: list) -> bool:
    """
    This function is responsible to check if the current user is a member of the privileged groups.
    """
    for group in current_groups:
        if group in privileged_groups:
            return True
    return False


def filter_subdict_by_key(dict_with_dict_values: dict, key: str, value) -> list:
    """
    This function is responsible to return filtered subdict from dict.
    for example
    {
        "a": {
                "category": "server",
                "data": "aaa",
                ...
            },
        "b": {
            "server": "instance",
            "data": "bbb",
            ...
        },
        "c": {
            "server": "server",
            "data": "ccc",
            ...
        }
    }
    filter_subdict_by_key(dict_with_dict_values, "server", "a server") will return
    [
    {
        "category": "server",
        "data": "aaa",
        ...
    },
    "c": {
        "server": "server",
        "data": "ccc",
        ...
    }

    ]
    """
    return [v for k, v in dict_with_dict_values.items() if v[key] == value]


def sort_subdict_by_key(dict_with_dict_values: dict, key: str) -> list:
    """
    This function is responsible to sort subdict from dict.
    """
    return [v for k, v in sorted(dict_with_dict_values.items(), key=lambda x: x[1][key])]


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


class MyArgumentParser(argparse.ArgumentParser):
    # Suppress the default error message
    def exit(self, status=0, message=None):
        return


def split_exclude_quotes(s):
    # Match quoted strings and non-quoted parts
    pattern = r'"([^"]*)"|\'([^\']*)\'|([^"\' ]+)'
    parts = re.findall(pattern, s)

    # Join non-empty parts and return
    return [p[0] or p[1] or p[2] for p in parts]


def generate_arg_parser():
    """
    This function is respponsible to manage the arguments passed to the script.
    """

    parser = MyArgumentParser(add_help=True, description="TDS client implementation (SSL supported).")

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
    module.add_argument("-chain-id", help="Chain ID to use", default=None, type=int)
    module.add_argument("-auto-yes", help="Auto answer yes to all questions", action='store_true', default=False)

    modules = parser.add_subparsers(title='Modules', dest='module')
    modules.add_parser('enumerate', help='Enumerate MSSQL server')
    set_chain = modules.add_parser('set-chain', help='Set chain ID (For interactive-mode only!)')
    modules.add_parser('get-chain-list', help='Get chain list')
    modules.add_parser('get-link-server-list', help='Get linked server list')
    set_chain.add_argument("chain", help="Chain ID to use", type=int)
    set_link_server = modules.add_parser('set-link-server', help='Set link server (For interactive-mode only!)')
    set_link_server.add_argument("link", help="Linked server to launch queries")
    command_execution = modules.add_parser('exec', help='Command to execute')
    command_execution.add_argument("-command-execution-method", choices=['xp_cmdshell', 'sp_oacreate'],
                                   default='xp_cmdshell')
    command_execution.add_argument("command", help="Command to execute")

    ntlm_relay = modules.add_parser('ntlm-relay', help='Steal NetNTLM hash / Relay attack')
    ntlm_relay.add_argument("smb_server", help="Steal NetNTLM hash / Relay attack (Example: 192.168.1.1)")
    ntlm_relay.add_argument("-relay-method", choices=['xp_dirtree', 'xp_subdirs', 'xp_fileexist'],
                            default='xp_dirtree')

    custom_asm = modules.add_parser('custom-asm', help='Execute procedures using custom assembly')
    custom_asm.add_argument("-arch", choices=['x86', 'x64', 'autodetect'], default='autodetect')
    custom_asm.add_argument("-procedure-name", choices=['execute_command', 'run_query', 'run_query_system_service'],
                            default='execute_command')
    custom_asm.add_argument("command", help="Command to execute")

    direct_query = modules.add_parser('direct_query', help='Execute direct query')
    direct_query.add_argument("query", help="Query to execute")
    direct_query.add_argument("-method", choices=['OpenQuery', 'exec_at'], default='OpenQuery')

    retrieve_passwords = modules.add_parser('retrieve-password', help='Retrieve password from ADSI servers')
    retrieve_passwords.add_argument("-listen-port",
                                    help="Port to listen on (default 1489)", type=int, default=1489)
    retrieve_passwords.add_argument("-adsi-provider", help="choose ADSI provider "
                                                           "(if not defined, it will choose automatically)",
                                    default=None)
    retrieve_passwords.add_argument("-arch", choices=['x86', 'x64', 'autodetect'], default='autodetect')
    modules.add_parser('interactive', help='Interactive Mode')

    return parser, list(modules.choices.keys())
