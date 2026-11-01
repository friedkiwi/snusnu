# OS/400 names used by SNA routing

| OS/400 setting | IBM term | Routing role |
| --- | --- | --- |
| `LCLNETID` | Local network ID | Qualifies CP and LU names; a SNA network can span multiple snusnu sites. |
| `LCLCPNAME` | Local control point name | APPN node identity, conventionally `NETID.CPNAME`. Adjacent node/link reachability is associated with the CP. |
| `LCLLOCNAME` | Default local location name | Default local APPC location/LU name, conventionally `NETID.LOCNAME`. Additional local locations/LUs can be configured. |
| `SYSNAME` | Current system name | OS/400 machine name; APPN uses CP and location names rather than this value. |
| `CHGTCPDMN HOSTNAME` | TCP/IP host name | DNS/host-table identity for IP; independent of SNA CP and LU names. |

IBM lists these as separate [network attributes](https://www.ibm.com/docs/en/i/7.6.0?topic=hpr-changing-network-attributes) and explicitly distinguishes [system name from APPN names](https://www.ibm.com/support/pages/changing-system-name). IBM calls the [local location name equivalent to a local LU name](https://www.ibm.com/docs/en/i/7.4.0?topic=glossary-l). An APPN node may have [additional local locations](https://www.ibm.com/docs/en/i/7.5.0?topic=hpr-creating-appn-location-lists); [remote location configuration](https://www.ibm.com/docs/en/i/7.5.0?topic=beginning-add-configuration-list-entries) records an LU/location and its owning remote CP separately. A CP [can itself act as an LU](https://www.ibm.com/docs/en/csfdcd/7.1.0?topic=bac-appn-control-point). The TCP/IP hostname is set separately with [CHGTCPDMN](https://www.ibm.com/docs/en/ssw_ibm_i_76/cl/chgtcpdmn.htm).

The V4R4 lab set `LCLNETID(SOLNET) LCLCPNAME(SNAB) LCLLOCNAME(SNAB)` on guest B. Thus `SOLNET.SNAB` spells both its CP name and its default location/LU name **in this configuration**. A's `CRTCTLAPPC ... RMTCPNAME(SNAB)` addresses B's CP, while `STRPASTHR RMTLOCNAME(SNAB)` names a remote location. A different system could have `LCLCPNAME(SNAB) LCLLOCNAME(PASSTHR)` and additional locations, producing `SOLNET.SNAB` for the node and `SOLNET.PASSTHR` for its default LU. The V5R4 template's `S1054504` system name and TCP/IP hostname are likewise equal by configuration, not by protocol definition.

Snusnu's authenticated `origin` or `site ID` identifies a router connection for policy and advertisement scope. It is **not** the OS/400 `LCLNETID`, `SYSNAME`, CP name or TCP/IP hostname. “Site name” is not the IBM field name used for the SNA network; use “network ID” when referring to `LCLNETID`.

The route advertisement therefore carries a **typed SNA resource**: a network-qualified CP for node adjacency, or a network-qualified LU/location for a service, optionally naming its hosting CP. It still hides the local encapsulation. A local ingress map can translate LLC MAC/SAP to the CP route before XID, or translate an APPC remote location to a specific LU route. A CP route alone does not claim that every LU hosted by that node is known or reachable through snusnu; explicit LU exports cover configured gateway services.
