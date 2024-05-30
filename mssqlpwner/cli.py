# Built-in imports
import sys
from getpass import getpass

# Third party library imports
from impacket.examples.utils import parse_target
from impacket import LOG
from impacket.examples import logger

# Local library imports
import mssqlpwner.utilities as utilities
from mssqlpwner.playbooks.playbooks import Playbooks

def console():
    # Init the example's logger theme
    logger.init()
    parser, _ = utilities.generate_arg_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        return

    options = parser.parse_args()

    if options.module == "brute":
        mssql_client = Playbooks("", "", options)
        mssql_client.bruteforce(options.target, options.ul, options.pl, options.hl, options.tl)
        return

    if not options.target:
        LOG.error("target must be supplied!")
        return

    if not options.module:
        LOG.error("Module must be supplied!")
        return

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None \
            and options.no_pass is False and options.aesKey is None:
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    mssql_client = Playbooks(address, username, options)

    if not mssql_client.connect(username, password, domain):
        return
    if not mssql_client.enumerate(print_state=False):
        return

    mssql_client.execute_module(options.chain_id, options.link_name, options)
    mssql_client.disconnect()

