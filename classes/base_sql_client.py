########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.1'
__email__ = ['El3ct71k@gmail.com']

########################################################

import copy
import logging
import utilities
from typing import Union, Literal
from impacket import tds
from impacket import LOG
from impacket import version
from impacket.tds import TDS_SQL_BATCH


class BaseSQLClient(object):
    def __init__(self, address: str, options) -> None:
        self.ms_sql = tds.MSSQL(address, int(options.port))
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
            "local_hostname": str(),
            "servers_info": dict()

        }
        self.execute_as = ""

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

    def custom_sql_query(self, query: str, wait: bool = True, decode_results: bool = True,
                         print_results: bool = False) -> Union[bool, dict]:
        """
        This function is responsible to execute the given query.
        """
        self.ms_sql.sendTDS(TDS_SQL_BATCH, (query + '\r\n').encode('utf-16le'))
        if self.debug:
            LOG.info(f"Query: {query}")
        if wait:
            tds_data = self.ms_sql.recvTDS()
            self.ms_sql.replies = self.ms_sql.parseReply(tds_data['Data'], False)
            return self.parse_logs(decode_results=decode_results, print_results=print_results)

        else:
            return True

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
        if print_results or self.debug:
            LOG.info(ret_val['results'])
        return ret_val

    def build_query_chain(self, flow, query: str, method: Literal["exec_at", "OpenQuery", "blind_OpenQuery"]):
        """
        This function is responsible to build a query chain.
        """
        method_func = utilities.build_exec_at if method == "exec_at" else utilities.build_openquery
        chained_query = query

        # If the first server is the current server, remove it
        flow = flow[1:] if flow[0] == self.state['local_hostname'] else flow
        for link in flow[::-1]:  # Iterates over the linked servers
            chained_query = method_func(link, chained_query)
        return chained_query

    def generate_query(self, query: str, linked_server: str,
                       method: Literal['OpenQuery', 'blind_OpenQuery', 'exec_at'] = "OpenQuery"):
        """
        This function is responsible to split a linked server path string in order to build chained queries through the
         linked servers using the OpenQuery or exec function.
        Example:
            Host -> Server1 -> Server2 -> Server3
            OpenQuery(Server1, 'OpenQuery(Server2, ''OpenQuery(Server3, '''query''')'')')
            EXEC ('EXEC (''EXEC ('''query''') AT Server3'') AT Server2') AT Server1
        """
        query = f"{self.execute_as}{query}"
        if not linked_server or not self.state['local_hostname'] or linked_server == self.state['local_hostname']:
            return query
        if method == "blind_OpenQuery":
            query = f"SELECT 1; {query}"
        if linked_server not in self.state['servers_info'].keys():
            LOG.error(f"Server {linked_server} is not linkable from {self.state['local_hostname']}")
            return None
        return self.build_query_chain(self.state['servers_info'][linked_server]['chain_tree'], query, method)

    def build_chain(self, query: str, linked_server: str,
                    method: Literal['OpenQuery', 'blind_OpenQuery', 'exec_at'] = "OpenQuery",
                    decode_results: bool = True, print_results: bool = False, wait: bool = True) -> dict:
        """
         This function is responsible to build the query chain for the given query and method.
        """
        query = self.generate_query(query, linked_server, method)
        return self.custom_sql_query(query, print_results=print_results, decode_results=decode_results, wait=wait)

    def disconnect(self) -> None:
        """
        This function is responsible to disconnect from the database.
        """
        self.ms_sql.disconnect()
