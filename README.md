# Enumeration
Enumeration Techniques

# Explore Google hacking and enumeration 
```
Developed by: SELVA KUMAR
Register no:212222110042

```
# AIM:

To use Google for gathering information and perform enumeration of targets

## STEPS:

### Step 1:

Install kali linux either in partition or virtual box or in live mode

### Step 2:

Investigate on the various Google hacking keywords and enumeration tools as follows:


### Step 3:
Open terminal and try execute some kali linux commands

## Pen Test Tools Categories:  

Following Categories of pen test tools are identified:
Information Gathering.

## Google Hacking:

Google hacking, also known as Google dorking, is a technique that involves using advanced operators to perform targeted searches on Google. These operators can be used to search for specific types of information, such as sensitive data that may have been inadvertently exposed on the web. Here are some advanced operators that can be used for Google hacking:

site: This operator allows you to search for pages that are within a specific website or domain. For example, "site:example.com" would search for pages that are on the example.com domain.
Following searches for all the sites that is in the domain yahoo.com

filetype: This operator allows you to search for files of a specific type. For example, "filetype:pdf" would search for all PDF files.
Following searches for pdf file in the domain yahoo.com



intext: This operator allows you to search for pages that contain specific text within the body of the page. For example, "intext:password" would search for pages that contain the word "password" within the body of the page.


inurl: This operator allows you to search for pages that contain specific text within the URL. For example, "inurl:admin" would search for pages that contain the word "admin" within the URL.

intitle: This operator allows you to search for pages that contain specific text within the title tag. For example, "intitle:index of" would search for pages that contain "index of" within the title tag.

link: This operator allows you to search for pages that link to a specific URL. For example, "link:example.com" would search for pages that link to the example.com domain.

cache: This operator allows you to view the cached version of a page. For example, "cache:example.com" would show the cached version of the example.com website.

 
# DNS Enumeration


## DNS Recon
provides the ability to perform:
Check all NS records for zone transfers
Enumerate general DNS records for a given domain (MX, SOA, NS, A, AAAA, SPF , TXT)
Perform common SRV Record Enumeration
Top level domain expansion








## dnsenum
Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain. The program currently performs the following operations:

Get the host’s addresses (A record).
Get the namservers (threaded).
Get the MX record (threaded).
Perform axfr queries on nameservers and get BIND versions(threaded).
Get extra names and subdomains via google scraping (google query = “allinurl: -www site:domain”).
Brute force subdomains from file, can also perform recursion on subdomain that have NS records (all threaded).
Calculate C class domain network ranges and perform whois queries on them (threaded).
Perform reverse lookups on netranges (C class or/and whois netranges) (threaded).
Write to domain_ips.txt file ip-blocks.
This program is useful for pentesters, ethical hackers and forensics experts. It also can be used for security tests.


## smtp-user-enum
Username guessing tool primarily for use against the default Solaris SMTP service. Can use either EXPN, VRFY or RCPT TO.


In metasploit list all the usernames using head /etc/passwd or cat /etc/passwd:

select any username in the first column of the above file and check the same


# Telnet for smtp enumeration
Telnet allows to connect to remote host based on the port no. For smtp port no is 25
telnet <host address> 25 to connect
and issue appropriate commands
  
 
  
  

# nmap –script smtp-enum-users.nse <hostname>

The smtp-enum-users.nse script attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user accounts in the remote system.


## OUTPUT:
## site:
![Screenshot 2024-09-23 190243](https://github.com/user-attachments/assets/a7ebe25c-cf4c-4f33-aa5a-92d23354b9d8)


## filetype:
![image](https://github.com/user-attachments/assets/47022dca-8b58-4d09-b561-a2c6ab01a3e1)




## intext:
![image](https://github.com/user-attachments/assets/d993ca59-86c9-463a-9155-6bf99f853847)




## inurl:
![image](https://github.com/user-attachments/assets/f866e6e8-3e8f-4f9b-83c4-33e12a6ef8e8)


## intitle:

![image](https://github.com/user-attachments/assets/04f789a8-d968-4430-903d-082b43d75b5a)




## link:
![image](https://github.com/user-attachments/assets/1ace19b2-6fa8-44cd-a0fd-0832cfff0f60)




## cache:
![image](https://github.com/user-attachments/assets/abfa5a0d-5abf-46d3-a68f-8af00e0d261b)


## DNS Enumeration:
## DNS Recon:
![03a35941-20f5-41a4-886f-f7e72ffdbf14](https://github.com/user-attachments/assets/11440e4c-ab64-4cad-bd90-c94ef2c2aae3)


## dnsenum:
![2f96ce9e-2eff-4bfe-9719-49e8382398b3](https://github.com/user-attachments/assets/7edd5125-45c9-4116-842e-5e96f6bbc5c4)
![5c235bd2-b8fe-4a4e-8b85-e3f9793f1e68](https://github.com/user-attachments/assets/3ae424b4-8a6f-46a6-92c6-525d09ba1395)




## smtp-user-enum:
![7a65b918-f1d5-4e7e-bb4d-bce9bd1ad579](https://github.com/user-attachments/assets/2d1b973c-4a46-4999-978f-d71c32f5b3fc)



## nmap –script smtp-enum-users.nse :
![7a65b918-f1d5-4e7e-bb4d-bce9bd1ad579](https://github.com/user-attachments/assets/b7dabe75-888a-4ca3-933b-d794c7a5eaeb)


## RESULT:
The Google hacking keywords and enumeration tools were identified and executed successfully

