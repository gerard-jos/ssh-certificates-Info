# **SSH Certificate Authentication**

- **Table of contents**
  - [**CA-host:**](#ca-host)
  - [**ssh-keygen:**](#ssh-keygen)
  - [**Host-Certificate**](#host-certificate)
  - [**User-Certificate**](#user-certificate)
  - [**Host-Configuration**](#host-configuration)
  - [**User-Configuration**](#user-configuration)
  - [**Flags and additional information**](#flags-and-additional-information)
  - [**Sources**](#sources)

### **CA-host:**
On this host we create a CA-Certificate with the command below. 
```bash
ssh-keygen -t ed25519 -C 'ca@example.tld' -f ca-hosts
and
ssh-keygen -t ed25519 -C 'ca@example.tld' -f ca-users
``` 
 
This will create ```ca-hosts, ca-users``` and ```ca-hosts.pub, ca-users.pub```.  
Which will need to sign our Certificates.

### **ssh-keygen:**
Users and servers must use the latest ```ed25519``` ssh key-pairs.  
Later we will change them into Certificates.  
Use this command to create an new key-pair
```bash
ssh-keygen -t ed25519 
```
Futher in this document we'll go deeper into the ```ssh-keygen``` command.  
As it is vital for the signing process of the certificates.

### **Host-Certificate**
Locate ```/etc/ssh/ssh_host_ed25519_key.pub``` on the preferred host and copy content to the CA-host as 'example1.example.tld.pub' file.

then we can sign the key with the ssh-keygen command. 
```bash
ssh-keygen -s ca-hosts -h -I key-id -n host1.example.tld example1.example.tld.pub
```
* key-id can be the hostname of the host.
* -n is used to add the host's FQDN so that if it's cracked then it can only impersonate that particular server

Which will create: ```example1.example.tld-cert.pub``` .

Now copy the content of ```example1.example.tld-cert.pub``` to the host you want as ```/etc/ssh/ssh_host_ed25519_key-cert.pub``` .

### **User-Certificate**
Locate the user ```.pub``` file in ```~/.ssh/``` copy the content to the CA-host under the same name.

Then create a user-Certificate with 
```bash
ssh-keygen -s ca-users -I user@hostname -n username,username1 example.pub
```
* ***Note*** That ```-I``` the key identifier is the id that will be logged when authentication occurs.
* Also you can add an validity period by invoking ```-V``` followed by ```+52w1d2h```

Which will create ```example-cert.pub```

***Note*** the ```-n``` flag it's used to add a username to the principals list of the Certificate. A principal is a username on the server. The server will reject a client Certificate without a principal.

Now copy the cert.pub back to the users machine in the ```~/.ssh/``` Directory.

### **Host-Configuration**
On the host-side add the ```ca-users.pub``` content to ```/etc/ssh/ca-users.pub```. Ways to accomplish this are through the use of ```scp```. But there are other options available.  
Then add the following lines to /etc/ssh/sshd_config file
```ASCII
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub

TrustedUserCAKeys /etc/ssh/ca-users.pub
```
Restart the ```sshd``` service.

### **User-Configuration**
On the client-side we will edit ```~/.ssh/known_hosts``` file.  
Adding the following content:
```ASCII
@cert-authority *.example.tld followed by ca-hosts.pub content.
````
***Note*** the ip or better domain needs to match the host(s) you're trying to reach.

### **Summary of commands**
* ***(For CA creation)***
```bash
ssh-keygen -t ed25519 -C 'ca@example.tld' -f ca-hosts 
ssh-keygen -t ed25519 -C 'ca@example.tld' -f ca-users
```
* ***(Creation/signing Host-Certificate)***
```bash
ssh-keygen -s ca-hosts -h -I host1 -n host1.example.tld example1.example.tld.pub
```
* ***(Creating/signing User-Certificate)***
```bash
ssh-keygen -s ca-users -I user@hostname -n username,username1 example.pub
```
### **Flags and additional information**
- **Flags**
  - ```-s``` used for signing keys turning them to certs
  - ```-h``` specifies that key to be signed is a host key
  - ```-I``` specifies the key identifier thats being logged by successful authentication
  - ```-n``` is invoked to add principals to the certificate 
    - For user-certificates ```-n``` specifies allowed usernames comma seperated.
    - For host-certificates ```-n``` specifies the FQDN that the host is using.
  - ```-V``` is used to set validity period 
    - Allowed formats are:
    - w=weeks -d=days +52w5d
    - YYYYMMDDHHMM[SS] example: +202012310830
    - ```+``` sets until validity 
    - ```-``` sets the from validity
  - ```-L``` lists the certificate information
- **Additional information**  
Please also read the manual page on you're own machine.  
Because there is alot of valuable information hidden there.
```bash
man ssh-keygen
man sshd_config
man ssh-agent
```

### ***Sources***
* [1](https://smallstep.com/blog/use-ssh-certificates/)
* [2](https://blog.habets.se/2011/07/OpenSSH-certificates.html)
* [3](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/sec-creating_ssh_ca_certificate_signing-keys)
* [4](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/sec-distributing_and_trusting_ssh_ca_public_keys)
* [5](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/sec-signing_ssh_certificates)
* [6](https://www.google.com/search?hl=en&source=hp&ei=nFtuX67RE8H4kwXH5K_ABA&q=%22ssh-keygen+-s%22&oq=%22ssh-keygen+-s%22&gs_lcp=CgZwc3ktYWIQDFDPFljPFmD6HmgAcAB4AIABLIgBLJIBATGYAQCgAQKgAQGqAQdnd3Mtd2l6&sclient=psy-ab&ved=0ahUKEwiuj_jqmoXsAhVB_KQKHUfyC0gQ4dUDCAs)