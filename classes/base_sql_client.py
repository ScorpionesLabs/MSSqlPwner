########################################################
__author__ = ['Nimrod Levy']
__license__ = 'GPL v3'
__version__ = 'v1.2'
__email__ = ['El3ct71k@gmail.com']

########################################################

import copy
import logging
import re

import utilities
from impacket import tds
from impacket import LOG
from impacket import version
from playbooks import Queries
from typing import Union, Literal
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
            "servers_info": dict(),
            "hostname": ""
        }
        self.threads = []
        self.sub_uninformative_links = re.compile(r'\[([a-zA-Z0-9.]{1,50}-\d{1,50})-IMPERSONATION-(COMMAND|REVERT)]')

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
        query = f"{Queries.REVERT_IMPERSONATION} {query}"
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
            return utilities.return_result(True, "Query Timed-out", [])
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

    def generate_query(self, chain_id: str, query: str,
                       method: Literal['OpenQuery', 'blind_OpenQuery', 'exec_at'] = "OpenQuery") -> list:
        """
        This function is responsible to split a linked server path string in order to build chained queries through the
         linked servers using the OpenQuery or exec function.
        Example:
            Host -> Server1 -> Server2 -> Server3
            OpenQuery(Server1, 'OpenQuery(Server2, ''OpenQuery(Server3, '''query''')'')')
            EXEC ('EXEC (''EXEC ('''query''') AT Server3'') AT Server2') AT Server1
        """

        if not chain_id:
            yield query, 0
            return

        server_info = copy.deepcopy(self.state['servers_info'][chain_id])

        chain_tree = server_info['chain_tree']
        chained_query = utilities.build_query_chain(chain_tree, query, method)
        for new_query in self.add_impersonation_to_chain(server_info['chain_tree_ids'], chained_query):
            yield new_query, len(server_info['chain_tree_ids']) - 1

    def add_impersonation_to_chain(self, chain_tree_ids: list, chained_query):
        """
        This function is responsible to add impersonation to the chained query.
        """

        for i, chain_id in enumerate(reversed(chain_tree_ids)):
            server_info = self.state['servers_info'][chain_id]
            link_name = server_info['link_name']
            impersonation_prefix = f"[{link_name}-{i}-IMPERSONATION-COMMAND]"
            impersonation_suffix = f"[{link_name}-{i}-IMPERSONATION-REVERT]"
            if impersonation_prefix not in chained_query:
                continue
            no_impersonation_query = chained_query.replace(impersonation_prefix, "")
            no_impersonation_query = no_impersonation_query.replace(impersonation_suffix, "")
            yield from self.add_impersonation_to_chain(chain_tree_ids, no_impersonation_query)
            catch_payload = re.compile(fr'{re.escape(impersonation_prefix)}(.*?){re.escape(impersonation_suffix)}')
            for impersonation_command in self.impersonate_as(chain_id):

                payload = catch_payload.match(chained_query)
                if not payload:
                    continue
                new_inline_query = impersonation_command
                new_inline_query += f"{Queries.EXEC_PREFIX}"
                new_inline_query += utilities.escape_single_quotes(payload.group(1))
                new_inline_query += f"{Queries.EXEC_SUFFIX}{Queries.REVERT_IMPERSONATION}"
                impersonated_query = chained_query.replace(payload[0],
                                                           utilities.build_payload_from_template(
                                                               "[PAYLOAD]", new_inline_query,
                                                               len(chain_tree_ids) - i - 1))
                impersonated_query = impersonated_query.replace("[PAYLOAD]", "'[PAYLOAD]'")

                yield from self.add_impersonation_to_chain(chain_tree_ids, impersonated_query)
        yield self.sub_uninformative_links.sub("", chained_query)

    def build_chain(self, chain_id: str, query: str,
                    method: Literal['OpenQuery', 'blind_OpenQuery', 'exec_at'] = "OpenQuery",
                    decode_results: bool = True, print_results: bool = False,
                    adsi_provider: str = None, wait: bool = True,
                    indicates_success: list = None) -> Union[dict, utilities.CustomThread]:
        """
         This function is responsible to build the query chain for the given query and method.
        """
        ret_val = {}
        query_tpl = "[PAYLOAD]"
        if method == "blind_OpenQuery":
            query_tpl = f"SELECT 1; {query_tpl}"
        if adsi_provider:
            query_tpl = utilities.build_query_chain(adsi_provider, query_tpl, method)
        for query_tpl, i in self.generate_query(chain_id, query_tpl, method):
            chained_query = utilities.build_payload_from_template("[PAYLOAD]", query, i)
            chained_query = query_tpl.replace("[PAYLOAD]", chained_query)
            ret_val = self.custom_sql_query(chained_query, print_results=print_results, decode_results=decode_results,
                                            wait=wait, indicates_success=indicates_success)
            ret_val['template'] = query_tpl
            ret_val['iterations'] = i
            if ret_val['is_success']:
                return ret_val
        return ret_val

    def impersonate_as(self, chain_id: str) -> list:
        """
        This function is responsible to impersonate as a server or database principal.
        """
        raise NotImplementedError

    def disconnect(self) -> None:
        """
        This function is responsible to disconnect from the database.
        """
        self.ms_sql.disconnect()
