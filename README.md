
# Bug: You are unable to set the IP address using SConfig on Server Core

If you are attempting to set the IP address of your Server Core installation and are getting the following...

```
 Setting NIC to static IP…
 Failed to release DHCP lease.
 Result code: 83
 Method name: ReleaseDHCPLease
```

This is a known bug. You can set the IP address of your host using Powershell.

First, get the name of the Ethernet interface you would like to modify using `Get-NetAdapter`.

Next, you will want to remove any IP address from the adapter using `Remove-NetIPAddress`.

```
Remove-NetIPAddress -InterfaceAlias Ethernet0 -Confirm:$False
```

This will remove the IPv4 and IPv6 address from the 'Ethernet0' interface without prompting for confirmation.

Finally, set the IP address using `New-NetIPAddress`.

```
New-NetIPAddress -InterfaceAlias Ethernet0 -IPAddress 172.16.0.2 -PrefixLength 24 -DefaultGateway 172.16.0.1
```

You can now use **SConfig** to set the DNS servers accordingly.


# Installing Active Directory Domain Services

You can install Windows Active Directory Domain Services via one of two ways.
 * Using the **Server Manager** GUI.
 * Using Powershell.

Using Powershell is faster as it's just a one line command:

```
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
```

This will install all the required binaries and services needed for Windows Active Directory Domain Services. Once installation is complete, you will be able to create a new domain and domain controller or join to an existing domain.


# Creating a New Domain

Like installing Active Directory Domain Services, you can create a new Active Directory forest and Domain Controller either via **Server Manager**, or via Powershell. This section will cover how to use Powershell to create a new forest and domain. 

Microsoft's guidance and documentation recommend that the Domain Controller also function as a DNS server. By default, creating a new forest and domain will make your server a DNS server as well. For simplicity, these instructions don't deviate from the defaults. However, it's possible that you may have different considerations or want to separate the role of Domain Controller from DNS server.

To create a new Active Directory forest and Domain Controller, you'll invoke the `Install-ADDSForest` cmdlet. The only required argument for this cmdlet is `-DomainName`. This is our fully qualified domain name (FQDN) that will be the root domain of the forest. For non-production use, pick something that won't result in a collision. 

```
Install-ADDSForest -DomainName test.vmnet.local
```

One optional argument of interest is `-DomainNetbiosName`. By default, Windows selects the first part of our FQDN as the NetBIOS name, assuming it also meets the requirement/constraints of NetBIOS itself.

Examples:
 * In the above example if our FQDN is `test.vmnet.local`, then Windows selects `TEST` as the NetBIOS name.
 * If our FQDN is simply `example.com`, then Windows selects `EXAMPLE` as the NetBIOS name.

It might be beneficial to select a alternative NetBIOS name if Windows detects the default NetBIOS name is already in use or it doesn't comply with the constraints of NetBIOS.

```
Install-ADDSForest -DomainName test.vmnet.local -DomainNetbiosName Foo
```

Other arguments/flags can be specified to set the functional level of the domain forest with that of older version of Active Directory Domain Services (`-DomainMode`), where windows should keep the database file (`-DatabasePath`), where logs should kept (`-LogPath`), and so forth.

Upon invocation of the cmdlet, Windows will prompt you for a `SafeModeAdministratorPassword`. This is also known as the **Directory Services Restore Mode (DSRM)** password. This is a recovery password for your Domain Controller. Keep this in a safe place if you are deploying a Domain Controller into production.

Once you've entered and confirmed the DSRM password of your choice, Windows will create your new Active Directory forest and configure your host to act as a Domain Controller, complete with DNS Services (unless you otherwise specified). Once complete, the server will reboot automatically.

Congratulations! Your domain controller is setup!

## Other Cases

If you already have an existing Domain Controller and you'd like to promote your server to act as another controller, use the `Install-ADDSDomainController` cmdlet.

## References
 * https://learn.microsoft.com/en-us/powershell/module/addsdeployment/install-addsforest


# Managing a Domain Controller Remotely




# Windows Remote Management (WinRM) Configuration

Windows Server can be managed remotely using the aptly name Windows Remote Management (WinRM) functionality. This is a SOAP-based protocol that enables you to run management tools and remote Powershell sessions over HTTP and HTTPS. By default on Windows 7 and higher, the default ports are 5985 (HTTP) and 5986 (HTTPS).

It's important to note that by default, Windows Server only allows inbound WinRM connections from hosts on the same subnet. This can be rectified by using the **Windows Firewall with Advanced Security** management console and tuning the firewall rules for "Windows Remote Management". However, if you're running Server Core, this is less straightforward. You can still modify Windows Firewall rules using Powershell, but it's more complicated. See **Managing Windows Firewall with Powershell** for more details.

WinRM may also itself restrict which remote hosts are considered "trusted" and thus, which remote hosts may connect to it. You can see which hosts are considered "trusted" using the following command.

```
Get-Item wsman:\localhost\Client\TrustedHosts
```

To set which remote hosts are considered "trusted", you can use the following command:

```
Set-Item wsman:\localhost\Client\TrustedHosts -Value <IP_ADDRESS>
```

You can provide a range of IP addresses that are considered "trusted" or a comma-delimited list as well.

## References
 * https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting



# Managing Windows Firewall with Powershell

You can manage Windows Firewall using Powershell. The following is a basic walk through that shows how to enable or disable Windows Firewall from enforcing rules, along with a walk through on how to tune specific rules.

The first thing to remember is that Windows applies different firewall profiles to different network connection types (e.g. Public Network vs. Private Network). You may need to check which profile is being applied to your connection. You can check this using `Get-NetConnectionProfile`.

Example:
```
PS C:\Windows\system32\> Get-NetConnectionProfile


Name             : Network
InterfaceAlias   : Ethernet
InterfaceIndex   : 6
NetworkCategory  : Public
IPv4Connectivity : Internet
IPv6Connectivity : NoTraffic
```

We see from the above output for `NetworkCategory` that Windows is categorizing the network connection as `Public`. This means the Public firewall profile is also being applied to the connection.

We can also see which profiles are currently enabled with `Get-NetFirewallProfile`. The following command prints out a simplified table of the firewall profiles which are enabled or disabled:

```
Get-NetFirewallProfile | Select-Object -Property Name,Enabled
```

Example:
```
PS C:\Windows\system32\> Get-NetFirewallProfile | Select-Object -Property Name,Enabled

Name    Enabled
----    -------
Domain     True
Private    True
Public     True

```

Note that if a firewall profile is enabled, it doesn't necessarily mean that that set of rules is being enforced on your connection. It just means that that set of rules is enabled for use whenever Windows is connected to a network categorized as public/private/domain.

If you want to completely disable enforcement of these profiles in Windows Firewall, you can use `Set-NetFirewallProfile`. The following command disables the **Public**, **Private**, and **Domain** profiles from being applied to any connection.

```
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

To re-enable, change the `-Enabled` value to `True`. 

Note that you can specify which profiles you want enabled and which ones you want disabled.


## Fine Tuning Windows Firewall

Enabling or disabling the firewall is a blunt approach. We can fine tine rules so that we can still keep all profiles enabled.

To view all firewall rules (both enabled or disabled), we can use `Get-NetFirewallRule`. By default, this cmdlet will dump **all** firewall rules to the console, which can be overwhelming. The following command can be used to print only the firewall rule **Name** and **Display Name**, making it easier to identify ones we're interested in.

```
Get-NetFirewallRule | Select-Object -Property Name,DisplayName | Sort-Object -Property Name
```

Example:
```
PS C:\Windows\system32> Get-NetFirewallRule | Select-Object -Property Name,DisplayName | Sort-Object -Property Name

Name                                        DisplayName
----                                        -----------
ADDS-ICMP4-In                               Active Directory Domain Controller -  Echo Request (ICMPv4-In)
ADDS-ICMP4-Out                              Active Directory Domain Controller -  Echo Request (ICMPv4-Out)
ADDS-ICMP6-In                               Active Directory Domain Controller -  Echo Request (ICMPv6-In)
ADDS-ICMP6-Out                              Active Directory Domain Controller -  Echo Request (ICMPv6-Out)
ADDS-Kerberos-Password-TCP-In               Kerberos Key Distribution Center - PCR (TCP-In)
ADDS-Kerberos-Password-UDP-In               Kerberos Key Distribution Center - PCR (UDP-In)
ADDS-Kerberos-TCP-In                        Kerberos Key Distribution Center (TCP-In)
ADDS-Kerberos-UDP-In                        Kerberos Key Distribution Center (UDP-In)
ADDS-LDAPGCSEC-TCP-In                       Active Directory Domain Controller - Secure LDAP for Global Catalog (TCP...
ADDS-LDAPGC-TCP-In                          Active Directory Domain Controller - LDAP for Global Catalog (TCP-In)
ADDS-LDAPSEC-TCP-In                         Active Directory Domain Controller - Secure LDAP (TCP-In)
ADDS-LDAP-TCP-In                            Active Directory Domain Controller - LDAP (TCP-In)
ADDS-LDAP-UDP-In                            Active Directory Domain Controller - LDAP (UDP-In)
ADDS-NB-Datagram-UDP-In                     Active Directory Domain Controller - NetBIOS name resolution (UDP-In)
ADDS-NP-TCP-In                              Active Directory Domain Controller - SAM/LSA (NP-TCP-In)
ADDS-NP-UDP-In                              Active Directory Domain Controller - SAM/LSA (NP-UDP-In)
ADDS-RPCEPMAP-TCP-In                        Active Directory Domain Controller (RPC-EPMAP)
ADDS-RPC-TCP-In                             Active Directory Domain Controller (RPC)
ADDS-TCP-Out                                Active Directory Domain Controller (TCP-Out)
ADDS-UDP-Out                                Active Directory Domain Controller (UDP-Out)
ADWS-TCP-In                                 Active Directory Web Services (TCP-In)
ADWS-TCP-Out                                Active Directory Web Services (TCP-Out)
AllJoyn-Router-In-TCP                       AllJoyn Router (TCP-In)
AllJoyn-Router-In-UDP                       AllJoyn Router (UDP-In)
AllJoyn-Router-Out-TCP                      AllJoyn Router (TCP-Out)
AllJoyn-Router-Out-UDP                      AllJoyn Router (UDP-Out)
CoreNet-DHCP-In                             Core Networking - Dynamic Host Configuration Protocol (DHCP-In)
CoreNet-DHCP-Out                            Core Networking - Dynamic Host Configuration Protocol (DHCP-Out)
CoreNet-DHCPV6-In                           Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)
CoreNet-DHCPV6-Out                          Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-Out)
CoreNet-Diag-ICMP4-EchoRequest-In           Core Networking Diagnostics - ICMP Echo Request (ICMPv4-In)
CoreNet-Diag-ICMP4-EchoRequest-In-NoScope   Core Networking Diagnostics - ICMP Echo Request (ICMPv4-In)
CoreNet-Diag-ICMP4-EchoRequest-Out          Core Networking Diagnostics - ICMP Echo Request (ICMPv4-Out)
CoreNet-Diag-ICMP4-EchoRequest-Out-NoScope  Core Networking Diagnostics - ICMP Echo Request (ICMPv4-Out)
CoreNet-Diag-ICMP6-EchoRequest-In           Core Networking Diagnostics - ICMP Echo Request (ICMPv6-In)
CoreNet-Diag-ICMP6-EchoRequest-In-NoScope   Core Networking Diagnostics - ICMP Echo Request (ICMPv6-In)
CoreNet-Diag-ICMP6-EchoRequest-Out          Core Networking Diagnostics - ICMP Echo Request (ICMPv6-Out)
CoreNet-Diag-ICMP6-EchoRequest-Out-NoScope  Core Networking Diagnostics - ICMP Echo Request (ICMPv6-Out)
CoreNet-DNS-Out-UDP                         Core Networking - DNS (UDP-Out)
CoreNet-GP-LSASS-Out-TCP                    Core Networking - Group Policy (LSASS-Out)
CoreNet-GP-NP-Out-TCP                       Core Networking - Group Policy (NP-Out)
CoreNet-GP-Out-TCP                          Core Networking - Group Policy (TCP-Out)
CoreNet-ICMP4-DUFRAG-In                     Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)
CoreNet-ICMP6-DU-In                         Core Networking - Destination Unreachable (ICMPv6-In)
CoreNet-ICMP6-LD-In                         Core Networking - Multicast Listener Done (ICMPv6-In)
CoreNet-ICMP6-LD-Out                        Core Networking - Multicast Listener Done (ICMPv6-Out)
CoreNet-ICMP6-LQ-In                         Core Networking - Multicast Listener Query (ICMPv6-In)
CoreNet-ICMP6-LQ-Out                        Core Networking - Multicast Listener Query (ICMPv6-Out)
CoreNet-ICMP6-LR2-In                        Core Networking - Multicast Listener Report v2 (ICMPv6-In)
CoreNet-ICMP6-LR2-Out                       Core Networking - Multicast Listener Report v2 (ICMPv6-Out)
CoreNet-ICMP6-LR-In                         Core Networking - Multicast Listener Report (ICMPv6-In)
CoreNet-ICMP6-LR-Out                        Core Networking - Multicast Listener Report (ICMPv6-Out)
CoreNet-ICMP6-NDA-In                        Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)
CoreNet-ICMP6-NDA-Out                       Core Networking - Neighbor Discovery Advertisement (ICMPv6-Out)
CoreNet-ICMP6-NDS-In                        Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)
CoreNet-ICMP6-NDS-Out                       Core Networking - Neighbor Discovery Solicitation (ICMPv6-Out)
CoreNet-ICMP6-PP-In                         Core Networking - Parameter Problem (ICMPv6-In)
CoreNet-ICMP6-PP-Out                        Core Networking - Parameter Problem (ICMPv6-Out)
CoreNet-ICMP6-PTB-In                        Core Networking - Packet Too Big (ICMPv6-In)
CoreNet-ICMP6-PTB-Out                       Core Networking - Packet Too Big (ICMPv6-Out)
CoreNet-ICMP6-RA-In                         Core Networking - Router Advertisement (ICMPv6-In)
CoreNet-ICMP6-RA-Out                        Core Networking - Router Advertisement (ICMPv6-Out)
CoreNet-ICMP6-RS-In                         Core Networking - Router Solicitation (ICMPv6-In)
CoreNet-ICMP6-RS-Out                        Core Networking - Router Solicitation (ICMPv6-Out)
CoreNet-ICMP6-TE-In                         Core Networking - Time Exceeded (ICMPv6-In)
CoreNet-ICMP6-TE-Out                        Core Networking - Time Exceeded (ICMPv6-Out)
CoreNet-IGMP-In                             Core Networking - Internet Group Management Protocol (IGMP-In)
CoreNet-IGMP-Out                            Core Networking - Internet Group Management Protocol (IGMP-Out)
CoreNet-IPHTTPS-In                          Core Networking - IPHTTPS (TCP-In)
CoreNet-IPHTTPS-Out                         Core Networking - IPHTTPS (TCP-Out)
CoreNet-IPv6-In                             Core Networking - IPv6 (IPv6-In)
CoreNet-IPv6-Out                            Core Networking - IPv6 (IPv6-Out)
CoreNet-Teredo-In                           Core Networking - Teredo (UDP-In)
CoreNet-Teredo-Out                          Core Networking - Teredo (UDP-Out)
DeliveryOptimization-TCP-In                 Delivery Optimization (TCP-In)
DeliveryOptimization-UDP-In                 Delivery Optimization (UDP-In)
DfSMgmt-DCOM-In-TCP                         DFS Management (DCOM-In)
DfsMgmt-In-TCP                              DFS Management (TCP-In)
DfsMgmt-SMB-In-TCP                          DFS Management (SMB-In)
DfsMgmt-WMI-In-TCP                          DFS Management (WMI-In)
DFSR-DFSRSvc-In-TCP                         DFS Replication (RPC-In)
DFSR-DFSRSvc-RPCSS-In-TCP                   DFS Replication (RPC-EPMAP)
DNSSrv-DNS-TCP-In                           DNS (TCP, Incoming)
DNSSrv-DNS-UDP-In                           DNS (UDP, Incoming)
DNSSrv-RPCEPMAP-TCP-In                      RPC Endpoint Mapper (TCP, Incoming)
DNSSrv-RPC-TCP-In                           RPC (TCP, Incoming)
DNSSrv-TCP-Out                              All Outgoing (TCP)
DNSSrv-UDP-Out                              All Outgoing (UDP)
EventForwarder-In-TCP                       Remote Event Monitor (RPC)
EventForwarder-RPCSS-In-TCP                 Remote Event Monitor (RPC-EPMAP)
FileServer-ServerManager-DCOM-TCP-In        File Server Remote Management (DCOM-In)
FileServer-ServerManager-SMB-TCP-In         File Server Remote Management (SMB-In)
FileServer-ServerManager-Winmgmt-TCP-In     File Server Remote Management (WMI-In)
FPS-ICMP4-ERQ-In                            File and Printer Sharing (Echo Request - ICMPv4-In)
FPS-ICMP4-ERQ-Out                           File and Printer Sharing (Echo Request - ICMPv4-Out)
FPS-ICMP6-ERQ-In                            File and Printer Sharing (Echo Request - ICMPv6-In)
FPS-ICMP6-ERQ-Out                           File and Printer Sharing (Echo Request - ICMPv6-Out)
FPS-LLMNR-In-UDP                            File and Printer Sharing (LLMNR-UDP-In)
FPS-LLMNR-Out-UDP                           File and Printer Sharing (LLMNR-UDP-Out)
FPS-NB_Datagram-In-UDP                      File and Printer Sharing (NB-Datagram-In)
FPS-NB_Datagram-Out-UDP                     File and Printer Sharing (NB-Datagram-Out)
FPS-NB_Name-In-UDP                          File and Printer Sharing (NB-Name-In)
FPS-NB_Name-Out-UDP                         File and Printer Sharing (NB-Name-Out)
FPS-NB_Session-In-TCP                       File and Printer Sharing (NB-Session-In)
FPS-NB_Session-Out-TCP                      File and Printer Sharing (NB-Session-Out)
FPS-RPCSS-In-TCP                            File and Printer Sharing (Spooler Service - RPC-EPMAP)
FPSSMBD-iWARP-In-TCP                        File and Printer Sharing over SMBDirect (iWARP-In)
FPS-SMB-In-TCP                              File and Printer Sharing (SMB-In)
FPS-SMB-Out-TCP                             File and Printer Sharing (SMB-Out)
FPS-SMBQ-In-UDP                             File and Printer Sharing (SMB-QUIC-In)
FPS-SMBQ-Out-UDP                            File and Printer Sharing (SMB-QUIC-Out)
FPS-SpoolSvc-In-TCP                         File and Printer Sharing (Spooler Service - RPC)
KDSSVC-RPC-In-TCP                           Microsoft Key Distribution Service (RPC)
KDSSVC-RPCSS-In-TCP                         Microsoft Key Distribution Service (RPC EPMAP)
MDNS-In-UDP-Domain-Active                   mDNS (UDP-In)
MDNS-In-UDP-Private-Active                  mDNS (UDP-In)
MDNS-In-UDP-Public-Active                   mDNS (UDP-In)
MDNS-Out-UDP-Domain-Active                  mDNS (UDP-Out)
MDNS-Out-UDP-Private-Active                 mDNS (UDP-Out)
MDNS-Out-UDP-Public-Active                  mDNS (UDP-Out)
Microsoft-Windows-PeerDist-HostedClient-Out BranchCache Hosted Cache Client (HTTP-Out)
Microsoft-Windows-PeerDist-HostedServer-In  BranchCache Hosted Cache Server (HTTP-In)
Microsoft-Windows-PeerDist-HostedServer-Out BranchCache Hosted Cache Server(HTTP-Out)
Microsoft-Windows-PeerDist-HttpTrans-In     BranchCache Content Retrieval (HTTP-In)
Microsoft-Windows-PeerDist-HttpTrans-Out    BranchCache Content Retrieval (HTTP-Out)
Microsoft-Windows-PeerDist-WSD-In           BranchCache Peer Discovery (WSD-In)
Microsoft-Windows-PeerDist-WSD-Out          BranchCache Peer Discovery (WSD-Out)
Microsoft-Windows-Unified-Telemetry-Client  Connected User Experiences and Telemetry
MSDTC-In-TCP                                Distributed Transaction Coordinator (TCP-In)
MSDTC-KTMRM-In-TCP                          Distributed Transaction Coordinator (RPC)
MSDTC-Out-TCP                               Distributed Transaction Coordinator (TCP-Out)
MSDTC-RPCSS-In-TCP                          Distributed Transaction Coordinator (RPC-EPMAP)
MsiScsi-In-TCP                              iSCSI Service (TCP-In)
MsiScsi-Out-TCP                             iSCSI Service (TCP-Out)
NETDIS-FDPHOST-In-UDP                       Network Discovery (WSD-In)
NETDIS-FDPHOST-Out-UDP                      Network Discovery (WSD-Out)
NETDIS-FDRESPUB-WSD-In-UDP                  Network Discovery (Pub-WSD-In)
NETDIS-FDRESPUB-WSD-Out-UDP                 Network Discovery (Pub WSD-Out)
NETDIS-LLMNR-In-UDP                         Network Discovery (LLMNR-UDP-In)
NETDIS-LLMNR-Out-UDP                        Network Discovery (LLMNR-UDP-Out)
NETDIS-NB_Datagram-In-UDP                   Network Discovery (NB-Datagram-In)
NETDIS-NB_Datagram-Out-UDP                  Network Discovery (NB-Datagram-Out)
NETDIS-NB_Name-In-UDP                       Network Discovery (NB-Name-In)
NETDIS-NB_Name-Out-UDP                      Network Discovery (NB-Name-Out)
NETDIS-SSDPSrv-In-UDP                       Network Discovery (SSDP-In)
NETDIS-SSDPSrv-Out-UDP                      Network Discovery (SSDP-Out)
NETDIS-UPnPHost-In-TCP                      Network Discovery (UPnP-In)
NETDIS-UPnPHost-Out-TCP                     Network Discovery (UPnP-Out)
NETDIS-UPnP-Out-TCP                         Network Discovery (UPnPHost-Out)
NETDIS-WSDEVNT-In-TCP                       Network Discovery (WSD Events-In)
NETDIS-WSDEVNT-Out-TCP                      Network Discovery (WSD Events-Out)
NETDIS-WSDEVNTS-In-TCP                      Network Discovery (WSD EventsSecure-In)
NETDIS-WSDEVNTS-Out-TCP                     Network Discovery (WSD EventsSecure-Out)
Netlogon-NamedPipe-In                       Netlogon Service (NP-In)
Netlogon-TCP-RPC-In                         Netlogon Service Authz (RPC)
NTFRS-NTFRSSvc-In-TCP                       File Replication (RPC)
NTFRS-NTFRSSvc-RPCSS-In-TCP                 File Replication (RPC-EPMAP)
PerfLogsAlerts-DCOM-In-TCP                  Performance Logs and Alerts (DCOM-In)
PerfLogsAlerts-DCOM-In-TCP-NoScope          Performance Logs and Alerts (DCOM-In)
PerfLogsAlerts-PLASrv-In-TCP                Performance Logs and Alerts (TCP-In)
PerfLogsAlerts-PLASrv-In-TCP-NoScope        Performance Logs and Alerts (TCP-In)
RemoteDesktop-In-TCP-WS                     Remote Desktop - (TCP-WS-In)
RemoteDesktop-In-TCP-WSS                    Remote Desktop - (TCP-WSS-In)
RemoteDesktop-Shadow-In-TCP                 Remote Desktop - Shadow (TCP-In)
RemoteDesktop-UserMode-In-TCP               Remote Desktop - User Mode (TCP-In)
RemoteDesktop-UserMode-In-UDP               Remote Desktop - User Mode (UDP-In)
RemoteEventLogSvc-In-TCP                    Remote Event Log Management (RPC)
RemoteEventLogSvc-NP-In-TCP                 Remote Event Log Management (NP-In)
RemoteEventLogSvc-RPCSS-In-TCP              Remote Event Log Management (RPC-EPMAP)
RemoteFwAdmin-In-TCP                        Windows Defender Firewall Remote Management (RPC)
RemoteFwAdmin-RPCSS-In-TCP                  Windows Defender Firewall Remote Management (RPC-EPMAP)
RemoteSvcAdmin-In-TCP                       Remote Service Management (RPC)
RemoteSvcAdmin-NP-In-TCP                    Remote Service Management (NP-In)
RemoteSvcAdmin-RPCSS-In-TCP                 Remote Service Management (RPC-EPMAP)
RemoteTask-In-TCP                           Remote Scheduled Tasks Management (RPC)
RemoteTask-RPCSS-In-TCP                     Remote Scheduled Tasks Management (RPC-EPMAP)
RRAS-GRE-In                                 Routing and Remote Access (GRE-In)
RRAS-GRE-Out                                Routing and Remote Access (GRE-Out)
RRAS-L2TP-In-UDP                            Routing and Remote Access (L2TP-In)
RRAS-L2TP-Out-UDP                           Routing and Remote Access (L2TP-Out)
RRAS-PPTP-In-TCP                            Routing and Remote Access (PPTP-In)
RRAS-PPTP-Out-TCP                           Routing and Remote Access (PPTP-Out)
RVM-RPCSS-In-TCP                            Remote Volume Management (RPC-EPMAP)
RVM-VDS-In-TCP                              Remote Volume Management - Virtual Disk Service (RPC)
RVM-VDSLDR-In-TCP                           Remote Volume Management - Virtual Disk Service Loader (RPC)
SLBM-MUX-IN-TCP                             Software Load Balancer Multiplexer (TCP-In)
SNMPTRAP-In-UDP                             SNMP Trap Service (UDP In)
SNMPTRAP-In-UDP-NoScope                     SNMP Trap Service (UDP In)
SPPSVC-In-TCP                               Key Management Service (TCP-In)
TPMVSCMGR-RPCSS-In-TCP                      TPM Virtual Smart Card Management (DCOM-In)
TPMVSCMGR-RPCSS-In-TCP-NoScope              TPM Virtual Smart Card Management (DCOM-In)
TPMVSCMGR-Server-In-TCP                     TPM Virtual Smart Card Management (TCP-In)
TPMVSCMGR-Server-In-TCP-NoScope             TPM Virtual Smart Card Management (TCP-In)
TPMVSCMGR-Server-Out-TCP                    TPM Virtual Smart Card Management (TCP-Out)
TPMVSCMGR-Server-Out-TCP-NoScope            TPM Virtual Smart Card Management (TCP-Out)
vm-monitoring-dcom                          Virtual Machine Monitoring (DCOM-In)
vm-monitoring-icmpv4                        Virtual Machine Monitoring (Echo Request - ICMPv4-In)
vm-monitoring-icmpv6                        Virtual Machine Monitoring (Echo Request - ICMPv6-In)
vm-monitoring-nb-session                    Virtual Machine Monitoring (NB-Session-In)
vm-monitoring-rpc                           Virtual Machine Monitoring (RPC)
W32Time-NTP-UDP-In                          Active Directory Domain Controller - W32Time (NTP-UDP-In)
Wininit-Shutdown-In-Rule-TCP-RPC            Inbound Rule for Remote Shutdown (TCP-In)
Wininit-Shutdown-In-Rule-TCP-RPC-EPMapper   Inbound Rule for Remote Shutdown (RPC-EP-In)
WINRM-HTTP-Compat-In-TCP                    Windows Remote Management - Compatibility Mode (HTTP-In)
WINRM-HTTP-In-TCP                           Windows Remote Management (HTTP-In)
WINRM-HTTP-In-TCP-PUBLIC                    Windows Remote Management (HTTP-In)
WMI-ASYNC-In-TCP                            Windows Management Instrumentation (ASync-In)
WMI-RPCSS-In-TCP                            Windows Management Instrumentation (DCOM-In)
WMI-WINMGMT-In-TCP                          Windows Management Instrumentation (WMI-In)
WMI-WINMGMT-Out-TCP                         Windows Management Instrumentation (WMI-Out)
```

We can also pass arguments to `Get-NetFirewallRule` to further filter our results.

If we want to modify the firewall rule which restricts what remote addresses can connect to WinRM locally, we need to know the name of the firewall rule. In this case, we need to find "Windows Remote Management (HTTP-In)", but the public rule. Based on the results returned above, we know that that is `WINRM-HTTP-In-TCP-PUBLIC`. 

To view the rule details, we can use `Get-NetFirewallRule`.

Example:
```
PS C:\Windows\system32\> Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC"


Name                          : WINRM-HTTP-In-TCP-PUBLIC
DisplayName                   : Windows Remote Management (HTTP-In)
Description                   : Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]
DisplayGroup                  : Windows Remote Management
Group                         : @FirewallAPI.dll,-30267
Enabled                       : True
Profile                       : Public
Platform                      : {}
Direction                     : Inbound
Action                        : Allow
EdgeTraversalPolicy           : Block
LooseSourceMapping            : False
LocalOnlyMapping              : False
Owner                         :
PrimaryStatus                 : OK
Status                        : The rule was parsed successfully from the store. (65536)
EnforcementStatus             : NotApplicable
PolicyStoreSource             : PersistentStore
PolicyStoreSourceType         : Local
RemoteDynamicKeywordAddresses : {}
PolicyAppId                   :
```

Note that the `RemoteAddress` value is not printed. We need to pipe the output of `Get-NetFirewallRule` to `Get-NetFirewallAddressFilter`:

Example:
```
PS C:\Windows\system32> Get-NetFirewallRule -Name WINRM-HTTP-In-TCP-PUBLIC | Get-NetFirewallAddressFilter


LocalAddress  : Any
RemoteAddress : LocalSubnet
```

Microsoft's documentation states that you can set the `RemoteAddress` value to `Any` using the following command. 

```
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress Any
```

For a test environment, this might be fine. However, for production it's strongly recommended you tune this rule to your specific needs to prevent unwanted unauthorized access. You can specify a specific subnet that should be able to remotely access WinRM. 

Example:
```
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress 172.16.1.48/28
```

You can verify that this rule was set using the `Get-NetFirewallRule` and `Get-NetFirewallAddressFilter` cmdlets as shown above.

If you'd like to reset the value of this specific rule back to its default:

```
PS C:\Windows\system32> $fwrule = Get-NetFirewallRule -Name WINRM-HTTP-In-TCP-PUBLIC | Get-NetFirewallAddressFilter
PS C:\Windows\system32> Set-NetFirewallAddressFilter -InputObject $fwrule -RemoteAddress "LocalSubnet"
```

## References:
 * https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-with-command-line
 * https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewalladdressfilter
 * https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule
 * https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewalladdressfilter
 * https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallrule