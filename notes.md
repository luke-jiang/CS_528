
## 1. Intro to Network security

### 1.1 CIA Properties

Network system expectations under benign conditions:

- correctly
- efficiently
- reliably

When consider adversarial attacks, we need to require **securely**

CIA of security goals:

- confidentiality: against *information exposure*
  - hide text (encryption)
  - hide metadata (mixes, onion-routing)
  - data privacy (access control, differential privacy)
  - mitigate information leakage (information-flow analysis)
  - hide existence of communication (cover traffic, steganography)
- integrity: correctness, against *bad outputs* and *tempering*
  - message integrity (MAC, signatures)
  - source authentication (signatures, credentials)
  - de-duplication (timestamp, counters, nonce, logging)
  - completeness (signatures, broadcasting)
- availability: against *DoS attacks*, *degradation of performance*
  - service availability: client puzzles, CAPTCHA
  - freedom of expression: steganography. covert communication

### 1.2 Network Adversaries

Different types of attackers:

- local (running on the computer)
  - eavesdrop, inject, modify, block, ...
  - in both directions
- man-in-the-middle (MitM) (eavesdropper, active attacker)
  - eavesdrop, inject, modify, block, ...
  - in both directions
  - e.g. router, ISP, DNS
- off-path (spoofer)
  - can only inject
- client (zombie, bot)
- server (phishing, cross-site)
- profiler

### 1.3 Threat Models and Tools

Threat Analysis:

- identify assets and entities
- identify relevant threats
- identify vulnerabilities of assets
- identify adversaries and capabilities
Perform risk vs. cost for each threat
  - what is the risk of not preventing the threat?
  - what is the cost of implementing prevention means?

Active vs. Passive:
Passive Adversaries comply with the functionalities of a protocol, but it trys obtaining more information in the process.

Tools of Network Security:

- cryptography: helps with confidentiality and integrity, but not availability
- access control: OS ensures correct access of processes
- SW/HW architecture
- monitoring and analysis (proactive and reactive)
- intrusion detection, recovery and response

Good security protocol is usually linear for the good guy and exponential for the bad guy.

### 1.4 Security Principles

- keep it simple and stupid
  - fewer errors
  - ease for testing and verification
  - higher interest among developers
- open design
  - avoid security by obscurity
- detection is often enough to deter an attacker
- principle of least priviledge
  - granularity of priviledges
- principle of separation of priviledge
  - system should grant permission on *multiple* conditions
- principle of complete mediation
  - all accesses must be checked, no default access
- principle of fail-safe default
  - the initial (default) access of an object should always be none
- principle of least common mechanism
  - no shared access. e.g. VM, sandboxes
- principle of psycological acceptability
  - security mechanisms should not be too complex s.t. users are not willing to use
  - should not assume users will comply.
  - e.g. dancing pigs: when ask a user to choose a securitu mechanism vs. dancing pigs, users always choose the latter

## 2. Symmetric Cryptography

### 2.1 Basics of Crypto

Basic goal of crypto:
Ensure secure communication over insecure medium

Substitution Ciphers:

- key space: permutations of `Σ = {A, B, C, ..., Z}`
- Encryption: given a key `π`, each letter `X` in the plaintext `P` is replaced with `π(X)`
- Decryption: each letter `Y` in the ciphertext `P` is replaced with `π^{-1}(x)`
- Vulnerable to frequency analysis

One-time Pad:

- plaintext space = ciphertext space = key space = `{0, 1}`
- key is chosen uniformly at random
- ciphertext = plaintext ⊕ key
- use xor for encryption and decryption
- has perfect security (reveals no info about the plaintext)
- cannot use a key twice, otherwise it's not one-time pad anymore.
- perfect secrecy requires key length >= message length.

Stream Cipher:

- replace random stream by *pseudorandom* string, using PRNG (Pseudo Random Number Generator).
  - PRNG expands a short random seed into a long pseudorandom string.
  - PRNG is a deterministic algorithm.
  - an adversary cannot distibguish a pseudorandom string from a truly random one.
- use the secret key as the seed.
- `E[M] = M ⊕ PRNG(key)`
- stream ciphers are very fast

Adversarial Models for Ciphers:

- ciphertext-only attack: adversary knows only a number of ciphertexts
- known-plaintext attack: adversary knows some (plaintext, ciphertext) pairs
- chosen-plaintext attack: adversary can choose some plaintext messages and obtain their ciphertexts. **This is the minimum required security today**
- chosen-ciphertext attack: adversary can choose some ciphertext messages and obtain their plaintexts

Chosen-Plaintext Attack (CPA) Game:

- attacker can obtain any number of (plaintext, ciphertext) pairs
- when ready, he chooses two plaintext M0 and M1, and get two ciphertexts
- adversary wins if he can discern which ciphertext corresponds to which plaintext.

## 3. Link Layer Security

### 3.1 ARP Cache Poisoning

OSI Protocol Stack:

- physical < Ethernet < IP < TCP/UDP < RPC < Application
- Link Layer refers to the Ethernet Layer

IP address vs. LAN Address:

- IP addresses are 32-bit network-layer address. They are used to route to destination network and change as the device moves.
- LAN (a.k.a MAC) addresses identify src/dst on the same network. They are 48 bits and are mostly not configurable.

Address Resolution Protocol (ARP):

- sender knows the IP address of the receiver
- must know the MAC address associated to the receiver to perform routing
- ARP protocol generates an ARP table that can be looked up by switches/routers.
- each entry in ARP table has an TTL value s.t. when a node leaves, its old entry does not exist forever.

Mechanism of ARP:
Suppose A wants to know C's MAC:

1. A broadcasts the query to all nodes
2. When C receives the query, C will send the info back to A
3. Other nodes will ignore A's request.

ARP poisoning Attack:

- `A` uses ARP broadcast to find `B`
- `E` answers. Consequently, `A` uses `E`'s link address
- `E` can then forward to `B`, becomes MitM

Prevention of ARP Poisoning:

- static ARP table: not scalable because machines move
- monitor potential ARP attacks and figure out who is the attacker.
- separate networks by routers not switch.

### 3.2 Wireless Communication

Base station approach vs. Ad-Hoc approach:

- Base stations are access points (AP). Each AP coverages an area and a device connects to an AP when it's in range.
- Ad-hoc approach has no base station. Wireless hosts communicate with each other directly.

Joining a new BSS:

- Beacon frames sent from AP
  - every 100ms, but configurable
  - details of the base station (timestamp, SSID, etc)
- Probe request/response
- Node then authenticates itself to AP

Security issues:

- anyone with radio can eavesdrop (sniffing)
- jamming: send signals and cause DoS attack
  - hard to combat
- rogue APs
- an open AP may be used by illegal activities and cause the AP owner to be prosecuted

How to lockdown APs:

- MAC whitelisting. Problem: don't scale well and vulnerable to sniffing/spoofing
- don't broadcast SSID (wireless device identifier). Problem: it can still be sniffed
- **WEP**: a linked layer protocol
  - used in industry
  - share a single cryptographic key across multiple users
  - packets are encrypted, cannot be sniffed

### 3.3 WEP Weeps

How WEP works:

- Assume ∃ client `C` and an access point `AP`
- `C` sends an authentication request to `AP`
- `AP` responds with a challenge in plaintext
- Client encrypts the challenge text and sends the ciphertext back to `AP`
- If properly encrypted, `AP` allows communication.

WEP Data Encryption:

- compute integrity checksum `c(M)` and append to original message `M` to get `P = M ++ c(M)`
- generate key-stream using RC4 encryption on a 24-bit `IV` concatenated to a pre-shared key
- `ciphertext = P ⊕ RC4(IV, key)`
- transmit IV and ciphertext

WEP Data Dncryption:

- extract `IV` and ciphertext
- `P' = ciphertext ⊕ RC4(IV, key) = P`
- `M'`, `c'` = `P'`
- compute `c(M')` and check `c(M') =?= c'` (integration check)

Attacks on WEP:

- WEP allows IV to be reused with any frame. Similar to the two-time pad problem, it's possible to get the xor of two plaintexts
- some card just set IV to zero
- CRC has property c(x ⊕ y) = c(x) ⊕ c(y), which enables modification of the ciphertext but still pass the WEP integration check
- IP redirection: trick the AP to decrypt ciphertext for the attacker

### 3.4 WPA/WPA2

Goal for WPA is to replace WEP without hardware replacement.

WPA enhancements:  
WPA uses Temporal Key Integrity Protocol (TKIP) and Extensible Authentication Protocol (EAP) to provide *dynamic key encryption* (key changes for every use) and *mutual authentication* (no rogue APs)

TKIP:

- protocol periodically updates the key for each client
- key size increased to 128 bits
- uses Message Integraty Check (MIC) instead of CRC
  - does not have the homomorphic property

EAP:
The authentication server verifies both the AP and the client.

## 4. TCP/IP Attacks and Security

### 4.1 TCP/IP Basics

IP Layer:

- uses numeric addresses for routing
- connectionless, best-effort protocol

IP Protocol Functionalities:

- packet fragmentation and reassembly
- error reporting: ICMP packets to source if packet dropped
- TTL field: decremented after every hop to prevent infinite loop

TCP protocol:

- sender breaks data into packers, each is attached with a sequence of number
- receiver reassembles packets in correct order
- lost packets are resent
- connection state is maintained on both sides

ICMP (control message protocol):  
error reporting, reachability, ...

### 4.2 IP Security

IP Packet Sniffing:

- Network Interface Card (NIC) has promiscuous mode to read all passing data
- unencrypted data are visible for sniffers

IP Packet Spoofing:

- An attacker can pretend to be any IP address
- e.g. DoS by amplification

Spoofing w/ Amplification:

- Attacker pretends to be the victim and send broadcast
- all replies go to the victim
- famous attack: Smurf DoS using ICMP

ICMP Echo:

- attacker uses icmp to map the network topology

Defend against IP spoofing:

- ingress filtering
  - forbid inbound broadcasts from the internet or private networks into your network
- egress filtering
  - make your network less attractive to attackers
  - drop outbound broadcasts

IP Fragmentation Attacks:

- fragmentation allows bypassing the maximum size of a packet
- reassembles packet larger than OS expected, causing OS to crash.

### 4.3 ICMP Attacks

ICMP Message Types:

- 0: echo reply
- 3: dest unreachable
- 4: source quench
- 5: redirect
- 8: echo

ICMP Dest Unreachable:

- DoS by sending forged ICMP unreachable packet
- defenses:
  - block icmp dest unreachable messages. But this may break other things
  - no defense if attacker is on the same network

ICMP Source Quench:

- ask the packets to be sent more slowly
- too much such requests can cause DoS
- solution: only allow ICMP source quench messages in the debugging mode

ICMP Redirect:

- send your packets to other gateways first, which are faster
- like spoofing, redirect packets to the attacker's gateway, causing MITM or DoS

Inverse Mapping Attack:

- attackers send packets to scan a network
- Solution: not allow ICMP messages to be sent

### 4.4 TCP Scanning and Spoofing

TCP handshake:

- ∃ Client C and Server S. SN := sequence number. AN := answer number
- C → S: SYN, SN_C ← rand_C, AN_C ← 0
- S → C: SYN/ACK, SN_S ← rand_S, AN_S ← SN_C
- C → S: ACK: SN ← SN_C + 1, AN ← SN_S

TCP SYN Scan:

- if you receives a SYN on a closed port, you need to send a RST w/ ACK flags acc. to the protocol
- *port scanning*: attacker can use this to scan the open ports to figure out what kind of machine it is

TCP ACK Scan:

- allows the attacker to know which IP addresses are in use (like ICMP ping)

Defend against scans:

- don't reply. But this blocks some functionalities
- active defense. e.g. in SYN scan, send a SYN/ACK for every packet to slow down scanners.

TCP Spoofing:

- TCP state is easy to guess: seq number is predictable
- attacker can inject packets into existing connections

### 4.5 DoS Attacks

SYN Flooding Attack:

- attacker sends lots of SYN packets to the victim server
- server allocates resources for each new request
- the heap memory of the server is exhausted
- asymmetry: attacker performs little computation, but server performs much more computation
- solutions:
  - use cookies s.t. server only allocates resource after connection is established
  - randomly delete some SYN requests
  - use a proxy (but privacy problem)

DoS by Connection Reset:

- attacker guesses the current sequence number of an existing connection
- attacker sends Reset packet to close it

DoS reflection and Asymmetry Attack:

- attacker, pretending to be the victim, sends a query to the server
- the query generates huge response from the server flooded to the victim

## 5. Public-Key Cryptography

### 5.1 Why do we need PKC

We should have secure and authenticated communication in TCP/IP stack (IPSEC, SSL/TLS)

Limitation of Symmetric Cryptography:

- sender and receiver must agree on a key beforehead
- cannot have a shared key in common before visiting a website
- client and server need to store too many keys, not scalable

Server creates two keys: public key and private key

- public key is open to all, both clients and adversaries. Public key is used for encryption
- private key is only visible to the server. Private key is used for decryption
- how to verify that a public key is associated to someone? use certificates
- encryption algorithm: **RSA-OAEP**

### 5.2 Public Key Encryption

Euler Totient Function:

- `ϕ(n)` := number of integers in `[1,n]` that are relatively prime to `n`
- if `n=pq` and `p`, `q` are primes, `ϕ(n) = (p-1)(q-1)`
- Euler's theorem: if `a ∈ Zₙ`, then `aᵠ⁽ⁿ⁾ = 1 mod n`

**RSA** Cryptosystem:

1. generate large primes `p` and `q`
2. compute `n=pq`. Note that `ϕ(n) = (p-1)(q-1)`
3. choose small `e`, relatively prime to `ϕ(n)`
4. compute unique `d` s.t. `ed = 1 mod ϕ(n)`
5. public key = `(e,n)`; private key = `d`

CPA/CCA Security for PKE:

- textbook RSA is not CPA-secure:
  - since textbook RSA is deterministic, an attacker can guess plaintext, compute ciphertext, and check for equality
  - in encryption, choose a randvar and prepend it before the plaintext to get the ciphertext
  - in decryption, the randvar is discarded
  - CPA-secure but not CCA-secure
- RSA-OEAP is CCA-secure

Disadvantages of PKC:

- long keys
- slower algorithm (can use hybrid encryption)

### 5.3 Digital Signatures

Non-repudiation: A party who signed cannot refute later.

When we associate `A`'s private key to `A`'s identity, anyone with `A`'s public key can verify `A`'s identity.

MAC vs. Digital Signature:

- MAC involves two parties but DS can be verified by many parties
- DS contains two algorithms:
  - signing :: m → private key → signature
  - verification :: m → public key → signature → bool
  - given public key (n,e) and private key d, signing <=> `s = hash(m)^d mod n`; verification <=> `sᵉ mod n = (hash(m)ᵈ)ᵉ mod n = hash(m)`

Existential forgery: An adversary should not be able to forge a signature for at least one message.

### 5.4 Signature Chain

Problem: Suppose ∃ `A`, `B`, `C` three parties. `A` have already mapped `PKc` to `C`. How can `A` trust `B` when `PKb` is not available to `A` but is to `C` (i.e, `A` gets trust of `B` from `C`)?

This is useful in certificate authorities

## 6. DNS Attacks and Security

### 6.1. DNS Basics

DNS maps domain names (in url) to IP addresses

DNS hierarchy:

- Root DNS servers
- top-level domains (.com, .org, .edu, ...)
- subdomains (google.com, pbs.org, purdue.edu, ...)

Caching is applied for repeated queries

DNS Resolution:

- user send query to *recursive resolver*
- recursive resolver through different levels of DNS servers in the hierarchy
- recursive resolver puts result into its *cache* and send it back to user

DNS Security Goal:

- correctness: the mappings are correct
- availability: no DoS attack
- privacy/confidentiality: not a goal

### 6.2 DNS Poisoning

Problem: no authentication for DNS responses

- attacker can provide spoofed records
- resolver caches
- client redirected to malicious hosts

Methods of DNS Poisoning:

- by gratuirous `glue` recursive resolver
  - e.g. query `A www.eve.com`
  - response `www.eve.vom NS download.com` and `download.con A 6.6.6.6`
  - defense: Bailiwick Rule: allow answers only for subdomains
- send from corrupt NS (name server)
- send spoofed DNS response:
  - attacker intercepts query send by RR to NS
  - attacker sends spoofed answer on behalf of NS and hope that its response arrives faster
  - now RR cache is contaminated
  - defenses: challenge-response defense (not effective) and cryptographic defense by DNSSEC

### 6.3 Kaminsky's attack

Kaminsky's obversation: high TTL cannot help with DNS IP spoofing attack

- attakers can ask for `1.bank.com`, `2.bank.com`, ...
- since each query is different, each triggers a request
- eventually attacker hits the transaction id `n` by `n.bank.com` and poisoning succeeds

Bernstein2002's solution: source port randomization

- send requests from random/unpredictable ports

### 6.4 DNSSEC

Goal: present off-path and MitM attacks

Method: sign DNS RRsets

Effect:prevent cache poisioning atacks

RR types of DNSSEC

- DNSKEY: public key of zone
  - KSK (key signing key): signs ZSK
  - ZSK (zone signing key): signs RRsets
- RRSIG: signature over an RRset
- Trust anchor → Parent Zone :{key signing key, zone signing key → Child Zone: {key signing key, zone sining key → txt resource}}
- depolyment of DNSSEC is often wrong

### 6.5. DNS Measures in Progress

## 7. SSL/TLS

### 7.1 SSL/TLS Basics

Most deployed security measurement, de facto standard for internet security

Client ↔ Server secure communication, unless attacker has complete control of the network

SSL/TLS has a long history and have several implementations (bugs, backword compatibility)

TLS has two sub-protocols: *handshake* protocol and *record* protocol:

- handshake protocol uses PKC to establish shared secrets between the client and the server
- record protocol: use the shared secrets to protect confidentiality, integrity, availability and authenticity of data exchange

Steps of SSL/TLS:

- Hello (client → server): protocol negotiation, agree on version/ciphersuite, determines all crypto algos
- KEM (server → client): authenticated key exchange, verify server/client identity, generate *master secret*, derive connection keys
- Finished (client → server): complete authentication, matches transcripts, authenticated encryption
- AppData (client → server): application data streams

### 7.2 SSL with RSA

Version Rollback Attack (chosen-protocol attack):

- messages in the `Hello` stage is plaintext, adversary can modify the text to use a less secure SSL version. Fixed in SSL 3.0
- defense is hard: must authenticate version early
- SSL 3.0's solution: version number is added to the pre-master secret (encrypted)

Bleichenbacher (Million Messages) Attack:

- RSA padding is not CCA-secure
- gradually reveal the content of the encrypted message

PFS (perfect forward secrecy) Problem:

- if RSA private key is stolen, then confidentiality of all previous sessions are broken.

### 7.3 Discrete Log Setting (Diffle-Hellman Exchange)




## 8. Public Key Infrastructure

## 9. Meta-data Privacy (Anonymity)

### 9.1 Need for Anonymity

Positive vs. Negative Effects of Anonymity:

- freedom of expression
- whistle-blowing
- avoid retribution
- bribery
- harassment and financial scams

Layers of Anonymities:

- unlinkable anon.: each action is anonymous
- linkable anon.: each action is linkable but still anonymous (don't know who does it, but know two actions are done by the same person)
- pseudonymity: there is a pseudonym that is registered and linked to all actions
- verinymity: each action is done with a real name

Anonymity Attackers:

- passive vs. active:
  - passive eavesdropping: traffic analysis
  - active attacks:
- global vs. local: global listens to all communications. local compromises just a few nodes.

Anonymity Set:

- an attacker cannot *sufficiently identify* the subject within an anonymity set.

### 9.2. Onion routing

Single Proxy:

- client ↔ proxy ↔ server
- proxy hides client's IP address
- drawbacks:
  - traffic analysis
  - trust on the proxy to not sell info

Multiple Proxies:

- client picks `n` proxies from a large pool of proxies
- client send packets through n proxies
- drawbacks:
  - one bad node breaks the anonymity completely
  - adversary can observe traffic pattern similarities at two locations

Onion Routing: Circuit Constructions
Establish symmetric keys between sender and proxy nodes s.t.

- only the sender and proxy node knows the key
- a proxy node does not know entities of other nodes on the path besides its neighbors

Onion Routing: Onion Transfer

- sender creates a layered encryption of message
- client: `kr(kg(kb(M)))` ↔ proxy `r: kg(kb(M)` ↔ proxy `g: kb(M)` ↔ proxy `b: M ↔ server`
- no single node (besides the final node) knows the message
- the final node does not know where the message comes from
- need public key cryptography to share the keys beforehead:
  - all proxies put their public keys in a directory accessible to all clients
  - client picks some IP addresses and their public keys from the directory

First Generation Onion-Routing Protocol:

- ∃ R, G, B. user sends `{kR, G {kG, B, {kB}_pkB}_pkG}_pkR`
- problem: no forward secrecy until public keys rotated

### 9.3. Tor Network

Need to introduce randomness on the client and server to achieve forward secrecy

Tor Protocol: multi-pass construction (*telescoping approach*) using key agreement

- client performs key exchange with the first proxy
- use the first node to perform key agreement with the second node,
- ...

1W-AKE Protocol:

- server has long-terms keys `(b, gᵇ)`
  - `b`: private key, `g`: public key
- client generates a randvar `x`, and computes `gˣ`
- server gets `gˣ`, retrieves `g` and send `gʸ` to the client
- client computes `hash(gʸˣ, gᵇˣ)`
- server computes `hash(gˣʸ, gˣᵇ)`
- attacker cannot figure out `gˣʸ` from knowing `gˣ` and `gʸ`

Tor project implements the onion routing protocol and achievel great success (most popular second to SSL/TLS)

Receiver Anonymity:
servers wants to hide its IP address

- server creates *introduction points* s.t. clients can reach these IPs but not the server directly
- server creates Tor circuits to IPs
- server puts its hidden service in a DB
- client retrieves the IP addresses of the introduction points together with server's public key
- client creates a Tor circuit to one of the introduction points and sets up a rendezvous points with the server
- client communicates the server with the rendezvous point

Tor goals and non-goals:

- forward secrecy and anonymity
- low latency
- low communication complexity
- not secure against global passive attackers
- not secure against end-to-end attacks, traffic analysis

### 9.4 Achieving Strong Anonymity

Anonymity Trinemma:
high anonymity, low handwidth overhead and low latency overhead are not simultaneously achievable.

Two categories for high anonymity:

- high-latency/bandwidth for large number of users
  - achieving traffic analysis resistance by routing though more nodes
  - e.g. mix-networks do not output packets in the same order as their arriving time
  - message sizes must be the same
  - pool mixing vs. continuous mixing
- low-latency with user coordination: dining crypto (DC) protocol
  - users in a collection of users send one message at a time
  - for each connection, a coin is tossed and its result is known by two parties of the connection
  - suppose user `A` wishes to send one-bit message `m ∈ {0, 1}`. For all other users, `m = 0`. For each user, it xors its `m` with the coin toss results and send it to a bulletin board. The bulletin board xors all inputs from users. Since each coin toss is applied twice, they cancel out and the bulletin board shows the one-bit message. The point is that other participants cannot determine who sent this message.
  - limitations:
    - collision happens when two parties send message simultaneously
    - active attacks

### 9.5 Censorship Circumvention

Suppression with accessing and publishing of information.

Targets of censorship:

- politics and religious comments
- topics antithetical to social norms and morals
- security
- economic interests

Means of censoring:

- IP blocking
- DNS filtering
- URL filtering
- deep packet inspection
- pulling out the cable

Undetectability: cannot determine whetehr a particular message exists or not.

Unobservability: undetectability + anonymity

Techniques:

- encryption s.t. ciphertext should be indistinguishable from a random string
- steganography / covert channels




## 11. Web Security

### 11.1 Web Security Basics

HTTP protocol:

- stands for *Hypertext Transfer Protocol*
- use *GET* to request data and *POST* to return data
- the protocol is stateless, i.e., each request is independent of previous requests
- Cookies are used to overcome the stateness:
  - created by servers
  - stored on the client browser
  - {name-of-cookie, server-domain, expiration, ...}
  - used for authentication, personalization, tracking

Goals of Web Security:

- safely browse the web (no information leak from a container). Visiting a malicious website should not affect: 
  - the browser or the OS 
  - other concurrently open tabs (cross-site)
  - delegated tabs from the malicious tab
- support secure web applications (just as secure as apps on local machines)

Browser Execution Model:

- Load Content
- Process HTML and executed scripts to render the content
- responds to user input events

### 11.2 Same Origin Policy (SOP) and Cross-Site Scripting (XSS)

Most browsers follow SOP:

- code originated from one website cannot access other pages, including code, DOM, cookies, cache, sending HTTP query and response, opening TCP/UDP connection
- how to define same site / different site? subdomains? same website might use different IPs?
- use [protocol + site + port] to define a set

Disable Malicious Scripts:

- run HTML in a sandbox can be too slow
- use allow-listing: disable scripting by default, let user enable it

XSS Attack:

- Most sites allow users to add/modify content (e.g. blogs, forums, ...)
- XSS means that a site unknowingly hosts and serves malicious script.
- e.g. A is a malicious user, B is the server, and C is the attacked. A modifies content in B by adding a script. When C access B, the malicious script would be executed on C.

XSS Reflection Attack:

- Attacker tricks the user to send crafted request to the site (via email phishing, etc)
- Server replies with page containing a script.
- scripts not only in `\<script\>`

### 11.3

Web Session:
- how?: HTTP authentication; cookies; identifier in url

Session Fixation Attack:
- Attacker A login to Server B
- B returns a session id to A
- A sends the link to B with the session id to a victim C
- C accesses the link and inputs its credentials
- A asks B for credentials, which returns C's credentials.





