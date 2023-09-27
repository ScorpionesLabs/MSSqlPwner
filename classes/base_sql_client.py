########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.3.2'
__email__ = ['El3ct71k@gmail.com']

########################################################

import copy
import logging
import utilities
from impacket import tds
from impacket import LOG
from typing import Union
from impacket import version
from playbooks import Queries
from impacket.tds import TDS_SQL_BATCH


class BaseSQLClient(object):
    def __init__(self, address: str, options) -> None:
        self.port = options.port
        self.ms_sql = tds.MSSQL(address, int(self.port))
        self.debug = options.debug
        self.options = options
        self.domain = None
        if options.debug is True:
            logging.getLogger("impacket").setLevel(logging.DEBUG)
            # Print the Library's installation path
            logging.debug(version.getInstallationPath())
        else:
            logging.getLogger("impacket").setLevel(logging.INFO)
        self.state = {
            "servers_info": dict(),
            "hostname": ""
        }
        self.threads = []

    def connect(self, username: str, password: str, domain: str) -> bool:
        """
        This function is responsible to connect to the server using the given credentials.
        """

        self.domain = domain.upper()
        self.ms_sql.connect()
        ret_val = False
        try:
            if self.options.k is True:
                ret_val = self.ms_sql.kerberosLogin(self.options.db, username, password, domain, self.options.hashes,
                                                    self.options.aesKey, kdcHost=self.options.dc_ip)
            else:
                ret_val = self.ms_sql.login(self.options.db, username, password, domain, self.options.hashes,
                                            self.options.windows_auth)
            self.ms_sql.printReplies()
        except Exception as e:
            logging.debug("Exception:", exc_info=True)
            logging.error(str(e))
        return ret_val

    def _custom_sql_query(self, query: str, decode_results: bool = True,
                          print_results: bool = False) -> Union[bool, dict]:
        """
        This function is responsible to execute the given query.
        """
        query = f"REVERT; {query}"
        self.ms_sql.sendTDS(TDS_SQL_BATCH, (query + '\r\n').encode('utf-16le'))
        if self.debug:
            LOG.info(f"Query: {query}")

        tds_data = self.ms_sql.recvTDS()
        self.ms_sql.replies = self.ms_sql.parseReply(tds_data['Data'], False)
        return self.parse_logs(decode_results=decode_results, print_results=print_results)

    def custom_sql_query(self, query: str, decode_results: bool = True,
                         print_results: bool = False, wait: bool = True, indicates_success: list = None) -> dict:

        th = utilities.CustomThread(target=self._custom_sql_query, args=(query, decode_results, print_results))

        # Start the threads
        th.start()
        # Wait for both threads to complete, with a timeout of 5 seconds

        # Check if the threads are still alive
        ret_val = th.join(timeout=5)
        if th.is_alive():
            if not wait:
                return utilities.return_result(True, "Query Timed-out", [], th)
            ret_val = th.join()
        if indicates_success and utilities.is_string_in_lists(indicates_success, ret_val['replay']):
            ret_val['is_success'] = True
        return ret_val

    def _parse_logs(self, decode_results: bool = False) -> dict:
        """
        This function is responsible to parse the logs and return the results.
        """
        replies = copy.deepcopy(self.ms_sql.replies)
        self.ms_sql.replies.clear()
        results = copy.deepcopy(self.ms_sql.rows)
        self.ms_sql.rows.clear()
        if decode_results:
            replies = utilities.decode_results(replies)
            results = utilities.decode_results(results)
        for keys in list(replies.keys()):
            for i, key in enumerate(replies[keys]):
                if key['TokenType'] == tds.TDS_ERROR_TOKEN:
                    reply = f"Line {key['LineNumber']}: {key['MsgText'].decode('utf-16le')}"
                    return utilities.return_result(False, reply, results)
                elif key['TokenType'] == tds.TDS_INFO_TOKEN:
                    reply = f"Line {key['LineNumber']}: {key['MsgText'].decode('utf-16le')}"
                    if 'Deferred prepare could not be completed' in str(reply):
                        return utilities.return_result(False, reply, [])
                    return utilities.return_result(True, reply, results)

                elif key['TokenType'] == tds.TDS_LOGINACK_TOKEN:
                    LOG.info("ACK: Result: %s - %s (%d%d %d%d) " % (
                        key['Interface'], key['ProgName'].decode('utf-16le'), key['MajorVer'], key['MinorVer'],
                        key['BuildNumHi'], key['BuildNumLow']))
                    reply = f"{key['Interface']} {key['ProgName'].decode('utf-16le')} {key['MajorVer']}" \
                            f" {key['MinorVer']} {key['BuildNumHi']} {key['BuildNumLow']}"
                    return utilities.return_result(True, reply, results)

                elif key['TokenType'] == tds.TDS_ENVCHANGE_TOKEN:
                    if key['Type'] in (tds.TDS_ENVCHANGE_DATABASE, tds.TDS_ENVCHANGE_LANGUAGE,
                                       tds.TDS_ENVCHANGE_CHARSET, tds.TDS_ENVCHANGE_PACKETSIZE):
                        record = tds.TDS_ENVCHANGE_VARCHAR(key['Data'])
                        if record['OldValue'] == '':
                            record['OldValue'] = 'None'.encode('utf-16le')
                        elif record['NewValue'] == '':
                            record['NewValue'] = 'None'.encode('utf-16le')
                        if key['Type'] == tds.TDS_ENVCHANGE_DATABASE:
                            _type = 'DATABASE'
                        elif key['Type'] == tds.TDS_ENVCHANGE_LANGUAGE:
                            _type = 'LANGUAGE'
                        elif key['Type'] == tds.TDS_ENVCHANGE_CHARSET:
                            _type = 'CHARSET'
                        elif key['Type'] == tds.TDS_ENVCHANGE_PACKETSIZE:
                            _type = 'PACKETSIZE'
                        else:
                            _type = "%d" % key['Type']
                        reply = f"ENVCHANGE({_type}): Old Value: {record['OldValue']}" \
                                f" New Value: {record['NewValue']}"
                        return utilities.return_result(True, reply, results)
        return utilities.return_result(True, "Query executed successfully", results)

    def parse_logs(self, print_results: bool = False, decode_results: bool = False) -> dict:
        """
        This function is responsible to print the results and return the results.
        """
        ret_val = self._parse_logs(decode_results=decode_results)
        if self.debug:
            LOG.info(ret_val['replay'])
        if print_results:
            LOG.info(ret_val['results'])
            pass

        return ret_val

    def build_query_chain(self, chain_tree: list, query: str,
                          method: str) -> list:
        """
        This function is responsible to build a query chain.
        """
        method_list = ['OpenQuery', 'exec_at']
        if method not in method_list:
            raise Exception(f"Method {method} not supported. Supported methods: {method_list}")

        if not chain_tree:
            yield query
            return

        link_name, chain_id = chain_tree.pop()
        query = self.configure_query_with_defaults(chain_id, query)
        new_query = Queries.link_query(link_name, query, method) if len(chain_tree) > 0 else query
        yield from self.build_query_chain(chain_tree, new_query, method)

    def generate_query(self, chain_id: str, query: str,
                       method: str = "OpenQuery") -> list:
        """
        This function is responsible to split a linked server path string in order to build chained queries through the
         linked servers using the OpenQuery or exec function.
        Example:
            Host -> Server1 -> Server2 -> Server3
            OpenQuery(Server1, 'OpenQuery(Server2, ''OpenQuery(Server3, '''query''')'')')
            EXEC ('EXEC (''EXEC ('''query''') AT Server3'') AT Server2') AT Server1
        """
        method_list = ['OpenQuery', 'exec_at']
        if method not in method_list:
            raise Exception(f"Method {method} not supported. Supported methods: {method_list}")

        if not chain_id:
            yield query
            return

        server_info = copy.deepcopy(self.get_server_info(chain_id))
        yield from self.build_query_chain(server_info['chain_tree'], query, method)

    def disconnect(self) -> None:
        """
        This function is responsible to disconnect from the database.
        """
        self.ms_sql.disconnect()

    def build_chain(self, chain_id: str, query: str, method: str = "OpenQuery",
                    decode_results: bool = True, print_results: bool = False, adsi_provider: str = None,
                    wait: bool = True, indicates_success: list = None,
                    used_methods: set = None) -> Union[dict, utilities.CustomThread]:
        raise NotImplementedError

    def configure_query_with_defaults(self, chain_id: str, query: str) -> str:
        """
        this function is responsible to add the default operations to a query
        """
        raise NotImplementedError

    def get_server_info(self, chain_id):
        raise NotImplementedError
