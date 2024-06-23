# Built-in imports
import sys
from getpass import getpass

# Third party library imports
from impacket.examples.utils import parse_target
from impacket import LOG
from impacket.examples import logger

# Local library imports
import mssqlpwner.utilities as utilities
from mssqlpwner.playbooks.playbooks import Playbooks, BruteForcer


def console():
    # Init the example's logger theme
    logger.init()
    parser, _ = utilities.generate_arg_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        return

    # Parse arguments
    options = parser.parse_args()

    # Check if help was requested
    if "-h" in sys.argv or "--help" in sys.argv:
        parser.print_help()
        return

    if options.module == "brute":
        BruteForcer(options).bruteforce(
            hosts_list=options.target,
            user_list=options.ul,
            password_list=options.pl,
            hash_list=options.hl,
            ticket_list=options.tl,
        )
        return

    # Check for required positional argument 'target'
    if not hasattr(options, "target") or not options.target:
        LOG.error("Target must be supplied!")
        return

    if not options.module:
        LOG.error("Module must be supplied!")
        return

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ""

    if (
        password == ""
        and username != ""
        and options.hashes is None
        and options.no_pass is False
        and options.aesKey is None
    ):
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    mssql_client = Playbooks(
        server_address=address, user_name=username, args_options=options
    )

    if not mssql_client.connect(username, password, domain):
        return

    if not mssql_client.enumerate(print_state=False):
        return

    mssql_client.execute_module(options.chain_id, options.link_name, options)
    mssql_client.disconnect()
