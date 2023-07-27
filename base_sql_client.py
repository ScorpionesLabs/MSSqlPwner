#!/usr/bin/env python

import copy
import logging
import utilities
from typing import Union
from impacket import tds
from impacket import LOG
from impacket.tds import TDS_SQL_BATCH


class BaseSQLClient(object):
    def __init__(self, address: str, options) -> None:
        self.ms_sql = tds.MSSQL(address, int(options.port))
        self.debug = options.debug
        self.is_authenticated = False
        self.options = options

    def connect(self, username: str, password: str, domain: str) -> None:
        """
        This function is responsible to connect to the server using the given credentials.
        """
        self.ms_sql.connect()
        try:
            if self.options.k is True:
                self.ms_sql.kerberosLogin(self.options.db, username, password, domain, self.options.hashes,
                                          self.options.aesKey, kdcHost=self.options.dc_ip)
            else:
                self.ms_sql.login(self.options.db, username, password, domain, self.options.hashes,
                                  self.options.windows_auth)
            self.ms_sql.printReplies()
            self.is_authenticated = True
        except Exception as e:
            logging.debug("Exception:", exc_info=True)
            logging.error(str(e))

    def custom_sql_query(self, query: str, wait: bool = True, decode_results: bool = True,
                         print_results: bool = False) -> Union[bool, dict]:
        """
        This function is responsible to execute the given query.
        """
        self.ms_sql.sendTDS(TDS_SQL_BATCH, (query + '\r\n').encode('utf-16le'))
        if wait:
            tds_data = self.ms_sql.recvTDS()
            self.ms_sql.replies = self.ms_sql.parseReply(tds_data['Data'], False)
            if self.debug:
                LOG.info(f"Query: {query}")
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
            LOG.info(ret_val['reply'])
        if print_results or self.debug:
            LOG.info(ret_val['results'])
        return ret_val

    def openquery(self, linked_server: str, query: str, print_results: bool = False,
                  decode_results: bool = False) -> dict:
        """
        This function is responsible to execute the given query using openquery.
        """
        self.custom_sql_query(utilities.build_openquery(linked_server, query))
        return self.parse_logs(print_results=print_results, decode_results=decode_results)

    def exec_at(self, linked_server: str, query: str, print_results: bool = False,
                decode_results: bool = False) -> dict:
        """
        This function is responsible to execute the given query using exec at.
        """
        self.custom_sql_query(utilities.build_exec_at(linked_server, query))
        return self.parse_logs(print_results=print_results, decode_results=decode_results)

    def disconnect(self) -> None:
        """
        This function is responsible to disconnect from the database.
        """
        self.ms_sql.disconnect()
