# Bastion
![image](https://github.com/user-attachments/assets/1c148a24-867a-470c-bdf2-51e98a04689c)

## About
Bastion is a unified SSH manager centralizing SSH connections and better pubkey management for LAN networks based on the concept of ProxyJumping through fortified bastion hosts. Bastion builds directly on the ssh protocol to remote connect to computers and proxies ssh connections from devices to other devices without needing to set up authentication directly between devices. Overall, this limits potential security leaks as firewall rules and public keys only need to be exchanged between the server hosting bastion and clients rather than between clients. If one client becomes compromised, it won't be as easy to compromise other clients in the network as reaching other clients requires going through the secured bastion server first. Bastion also is designed with redundancy and scalability in order to accomodate networks with a multitude of trusted connected devices. This simplified archictecture, in combination with adequate firewall configuration and antivirus protection, makes it significantly easier for network management. 

Similar strategies are often used in industry to efficiently and cleanly manage LAN networks, however their solutions are often tailored to their very specific use-cases and are relegated to internal tools or proprietary products. Additionally, similar functionality does exist through ssh with the `-J` flag, however ssh's implementation leaves a lot to be desired in terms of security, network design, and unified management. Bastion is completely free, open-source, and integrates directly into existing SSH infrastructure allowing for seamless integration into a variety of setups.

## Installation and Usage
To use bastion, first download and extract the compiled binaries. Optionally, you can add them to your path now. Then run `./bastion-srv` and `./bastion-auth` on your dedicated bastion server to start the connection manager and pubkey authentication manager. If you'd like to have ssh-keys expire, create a cron job that runs the command `./clean_authorized_keys <time limit in days>`. To register a client's public keys with bastion, run `./bastion <bastion_hostname or IPv4 address> --register` from another machine. If a machine has password authentication or no forms of restricted authentication, a client can reach it through bastion without that machine needing to be registered with bastion. If a machine  only uses pubkey authentication, it must have registered pubkeys as a client to bastion before another client can reach it through bastion. To reach a machine with bastion run `./bastion <bastion_hostname or IPv4 address> user@target_device_hostname_or_IP`.

## Example of how bastion simplifies a network
<div align="center">

| With Bastion | Without Bastion |
|---------|---------|
| ![with drawio](https://github.com/user-attachments/assets/8b4ab230-b36b-4ad2-a064-19d9cb25e05e) | ![without bastion drawio](https://github.com/user-attachments/assets/178bc095-f697-450c-8deb-45400dc54f0b) |
| **Diagram with bastion server** | **Diagram without bastion server** |    

</div>

As an example consider a network with 4 devices where each device may want to ssh into each other. Using password authentication, this requires each device knowing another devices password and connections occuring between every pair of devices. If you'd like to step up security and use public key authentication, this becomes even more risky as you're now sharing keys between every pair of devices. For any given network with $$n$$ devices, you'd have $\binom{n}{2}$ possible connections between two devices. When n becomes larger, say $$n=20$$, that would be $\binom{20}{2} = 190$ separate connections in a network and plenty of potential security vulnerabilities. Additionally, managing and authorizing that many connections becomes increasingly difficult at scale. 

On the other hand, using Bastion as a proxy means that every client only has a connection with the bastion server which means an administrator only needs to manage the connections between a client and Bastion. This is both easier to secure and reduces the number of connections that must be managed. For a network with $$n$$ devices, there is one connection to the bastion server for every other device, or $$n-1$$ connections. Using $$n=20$ that would be only 19 connections, compared to the 190 connections discussed earlier. Even if another bastion server was created for redundancy, that would only double the connections which does not scale nearly as quickly as $\binom{n}{2}$ connections does.

## Example of how bastion minimizes the effects of a security breach
<div align="center">

| With Bastion | Without Bastion |
|---------|---------|
| ![compromised_with_bastion drawio](https://github.com/user-attachments/assets/aaf06691-07ea-40ee-9072-ef74964fc5a7) | ![compromised_without_bastion drawio](https://github.com/user-attachments/assets/07062cde-4023-425a-b33c-bbf99333ead6) |
| **Diagram of a compromised machine with bastion server** | **Diagram of a compromised machine without bastion server** |    
</div>

In the event that a machine is compromised in a network without Bastion, all devices that share a connection with Bastion are directly connected to a compromised device. Therefore every device must be fortified significantly to prevent the entire network from being fully compromised. On the other hand, if a machine is compromised in a network using Bastion, then only Bastion needs to be secured to prevent connections leaking to the rest of the network. A compromised machine can easily be isolated and automatically blocked in this architecture.

## Example of redundancy with bastion
<div align="center">
  
![bastion_with_redundancy drawio](https://github.com/user-attachments/assets/d1805347-8b7c-4714-9324-a50b33d39b11)
  
</div>

Bastion can also be deployed in a redundant configuration. Because Bastion is built directly on ssh protocol, creating another jump point for the connection to proxy through is as simple as just creating a new Bastion server and using whichever one is available to reach a target machine. In the future, I hope to add key syncing and load balancing so that Bastion can automatically handle high volume connections.

## Security
Bastion's use of SSH means it is as secure as SSH and can be integrated with other security options (firewalls, antivirus, audits) to make the infrastructure as secure as possible. Inbound connections to the Bastion server use a similar re-implementation of Elliptic-curve Diffie-Hellman handhshake using OpenSSL, and any outbound connection from Bastion to a client simply uses another ssh process. To use bastion, a user must log into the Bastion server first before being redirected to another client. Additionally, if inbound connections that use Bastion are a concern, a machine can operate without being registered to Bastion (to prevent inbound connections) but still make outbound connections to the Bastion server regardless of registration status.  In the future I hope to improve the authentication mechanism with timeouts and combine Bastion with a custom antivirus implementation for additional security.

Thank you for visiting! If you have any comments or criticisms about the Bastion architecture please let me know. 
