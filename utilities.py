########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.3.2'
__email__ = ['El3ct71k@gmail.com']

########################################################

import os
import re
import json
import socket
import string
import random
import argparse
import binascii
import hashlib
from uuid import uuid4
from impacket import LOG
from threading import Thread
from typing import Any, Union


class CustomThread(Thread):
    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs: dict = None):
        if kwargs is None:
            kwargs = {}
        self._kwargs = None
        self._args = None
        self._target = None
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None

    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)

    def join(self, *args, **kwargs) -> Any:
        Thread.join(self, *args, **kwargs)
        return self._return


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


def generate_link_id() -> str:
    """
    This function is responsible to generate a unique link id.
    """
    return str(uuid4())


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


def remove_instance_name(server_name: str) -> str:
    """
    This function is responsible to remove the instance name from discovered server.
    Example:
        ServerName\\InstanceName -> ServerName
    """
    return server_name.split("\\")[0].strip()


def escape_single_quotes(query: str, amount: int) -> str:
    """
    This function is responsible to escape single quotes.
    """
    if amount <= 1:
        return query
    return query.replace("'", "'" * amount)


def escape_double_quotes(query: str, amount:  int) -> str:
    """
    This function is responsible to escape double quotes.
    """
    if amount <= 1:
        return query
    return query.replace('"', '"' * amount)


def _count_quotes(string_to_count, index, quote_type):
    """
    This inline-used function is responsible to count the number of quotes.
    """
    count = 0
    for i in range(index, 0, -1):
        if string_to_count[i] != quote_type:
            break
        count += 1
    return count


def count_quotes(my_str, index_to_find, quote_type):
    """
    This function is responsible to count the number of quotes.
    """
    container = my_str.replace(" ", "")
    try:
        index = container.index(index_to_find)
        if container[index - 1] == quote_type:   # and container[index + len(index_to_find)] == quote_type:
            amount = _count_quotes(container, index - 1, quote_type)
            return amount * 2
        return 0
    except ValueError:
        return 0


def format_strings(template, **kwargs):
    """
    This function is responsible to format the strings and add relevant amount of quotes.
    """
    for k, v in kwargs.items():
        for quote_type in ["'", '"']:
            amount = count_quotes(template, f"{{{k}}}", quote_type)
            if quote_type == "'":
                kwargs[k] = escape_single_quotes(kwargs[k], amount)
            else:
                kwargs[k] = escape_double_quotes(kwargs[k], amount)
    return template.format(**kwargs)


def replace_strings(template, dict_of_replacements):
    """
    This function is responsible to replace the strings and add relevant amount of quotes.
    """
    for find, replace in dict_of_replacements.items():
        for quote_type in ["'", '"']:
            amount = count_quotes(template, find, quote_type)
            if quote_type == "'":
                replace = escape_single_quotes(replace, amount)
            else:
                replace = escape_double_quotes(replace, amount)
            template = template.replace(find, replace)
    return template


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


def is_string_in_lists(first_list: list, second_list: list) -> bool:
    """
    This function is responsible to check if a string is in a list.
    """
    for item in first_list:
        if item in second_list:
            return True
    return False


def filter_subdict_by_key(dict_with_dict_values: dict, key: str, value) -> list:
    return sort_by_chain_length([v for k, v in dict_with_dict_values.items() if key in v.keys() and v[key] == value])


def sort_by_chain_length(dict_with_dict_values: list) -> list:
    return [d for d in sorted(dict_with_dict_values, key=lambda x: len(x["chain_tree"]))]


def return_result(status, replay, result, th: Union[None, CustomThread] = None):
    return {"is_success": status, "replay": replay, "results": result, "template": "", "thread": th}


def recursive_replace(my_content: Any, string_to_find: str, string_to_replace: str) -> Any:
    if isinstance(my_content, dict):
        container = dict()
        for k, v in my_content.items():
            container[k] = recursive_replace(v, string_to_find, string_to_replace)
        return container

    elif isinstance(my_content, list):
        container = list()
        for i, v in enumerate(my_content):
            container.append(recursive_replace(v, string_to_find, string_to_replace))
        return container

    elif isinstance(my_content, set):
        container = set()
        for i, v in enumerate(my_content):
            container.add(recursive_replace(v, string_to_find, string_to_replace))
        return container

    elif isinstance(my_content, str):
        if my_content == string_to_find:
            return string_to_replace
    return my_content


def detect_architecture(version) -> Union[str, None]:
    """
        This function is responsible to detect the architecture of a remote server.
    """
    for x64_sig in ["<x64>", "(X64)", "(64-bit)"]:
        if x64_sig in version:
            LOG.info("Architecture is x64")
            return "x64"
    for x86_sig in ["<x86>", "(X86)", "(32-bit)"]:
        if x86_sig in version:
            LOG.info("Architecture is x86")
            return "x86"
    return None


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


def is_port_open(host, port, timeout):
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout of 5 seconds
        sock.settimeout(timeout)

        # Attempt to connect to the host and port
        sock.connect((host, port))
        sock.close()
        # If the connection succeeds, the port is open
        return True
    except socket.error:
        # If an error occurs, the port is likely closed
        return False


def is_valid_ip(input_str: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, input_str)
        return True  # Valid IPv4 address
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, input_str)
            return True  # Valid IPv6 address
        except socket.error:
            return False  # Not a valid IP address


class MyArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        # Call the parent class's constructor
        super().__init__(*args, **kwargs)

        # Override the default behavior of -h/--help
        self._optionals.title = "Options"

    def error(self, message):
        # Override the default error message to not mention -h
        pass

    # Suppress the default error message
    def exit(self, status=0, message=None):
        return


def split_args(s):
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
    parser.add_argument('-timeout', action='store', default=30, help='timeout in seconds (default 30)', type=int)
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
    module.add_argument("-link-name", help="Linked server to launch queries", default=None)
    module.add_argument("-max-link-depth", help="Maximum links you want to depth recursively", default=10,
                        type=int)
    module.add_argument("-max-impersonation-depth", help="Maximum impersonation you want to depth in each link",
                        default=10, type=int)
    module.add_argument("-chain-id", help="Chain ID to use", default=None, type=str)
    module.add_argument("-auto-yes", help="Auto answer yes to all questions", action='store_true', default=False)

    modules = parser.add_subparsers(title='Modules', dest='module')
    modules.add_parser('enumerate', help='Enumerate MSSQL server')
    set_chain = modules.add_parser('set-chain', help='Set chain ID (For interactive-mode only!)')
    set_chain.add_argument("chain", help="Chain ID to use", type=str)
    modules.add_parser('rev2self', help='Revert to SELF (For interactive-mode only!)')
    modules.add_parser('get-rev2self-queries', help='Retrieve queries to revert to SELF (For interactive-mode only!)')
    get_chain_list = modules.add_parser('get-chain-list', help='Get chain list')
    get_chain_list.add_argument("-filter-hostname", help="Get filtered results with specific hostname", default=None,
                                type=str)
    modules.add_parser('get-link-server-list', help='Get linked server list')
    modules.add_parser('get-adsi-provider-list', help='Get ADSI provider list')
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

    inject_custom_asm = modules.add_parser('inject-custom-asm', help='Code injection using custom assembly')
    inject_custom_asm.add_argument("file_location", type=str, help='File location to inject')
    inject_custom_asm.add_argument("-procedure-name", type=str, default='Inject')

    direct_query = modules.add_parser('direct-query', help='Execute direct query')
    direct_query.add_argument("query", help="Query to execute")
    direct_query.add_argument("-query-method", choices=['OpenQuery', 'exec_at'], default='OpenQuery')

    retrieve_passwords = modules.add_parser('retrieve-password', help='Retrieve password from ADSI servers')
    retrieve_passwords.add_argument("-listen-port",
                                    help="Port to listen on (default 1489)", type=int, default=1389)
    retrieve_passwords.add_argument("-adsi-provider", help="choose ADSI provider "
                                                           "(if not defined, it will choose automatically)",
                                    default=None)
    retrieve_passwords.add_argument("-arch", choices=['x86', 'x64', 'autodetect'], default='autodetect')
    modules.add_parser('interactive', help='Interactive Mode')

    dynamic_brute = modules.add_parser('brute', help='Brute force')
    dynamic_brute.add_argument("-ul", help="User list", default="", required=True)
    dynamic_brute.add_argument("-pl", help="Password list", default="")
    dynamic_brute.add_argument("-hl", help="Hash List", default="")
    dynamic_brute.add_argument("-tl", help="Ticket List", default="")

    return parser, list(modules.choices.keys())
