# Splunk Cluster Architecture on AWS for Security Monitoring

## Objective:

The goal of this project is to design and implement a scalable Splunk Cluster Architecture hosted on AWS for centralized log management and real-time security monitoring. This system will ingest and process network security alerts from Snort IDS and DHCP logs from a Wi-Fi router. By leveraging the power of AWS infrastructure, this setup aims to provide robust and fault-tolerant data collection, analysis, and visualization capabilities, enhancing threat detection and network performance monitoring.



![Splunk Clustered Architecture Black](https://github.com/user-attachments/assets/cd2c503a-9cfc-4063-95f6-6d599d5105a1) </br>
REF 1 - SPLUNK CLUSTERED ARCHITECTURE


This project will provide a comprehensive understanding of both security monitoring and cloud-based architecture, allowing for the development of a flexible and scalable solution for real-time network analysis and threat detection.

## Skills Learned:

- Splunk Cluster Setup on AWS: Hands-on experience with deploying a distributed Splunk architecture on AWS, utilizing EC2 for compute resources.
- Data Ingestion: Configured Splunk to ingest and process various log formats, including Snort IDS alerts and router's DHCP logs.
- Security Monitoring and Analysis: Created dashboards and visualizations for monitoring security threats, network anomalies, and performance metrics.
- AWS Cloud Architecture: Gained expertise in setting up cloud-based infrastructure on AWS to support high availability and scalability of the Splunk cluster.
- Performance Optimization: Optimized Splunk's performance for high-volume log ingestion, ensuring smooth operations in a cloud-based, distributed environment.

## Tools Used:
- Splunk: For setting up a clustered architecture, log ingestion, parsing, and visualization.
- Snort IDS: For generating network intrusion detection alerts.
- Wi-Fi Router (DHCP Logs): To collect and process DHCP logs for monitoring network activity.
- Linux/Unix Servers: Used for configuring Splunk components on both on-premise and cloud environments.
- Splunk Apps/Technology Add-ons (TAs): Used for simplifying the integration of Snort and DHCP logs with Splunk.
- Amazon Web Services (AWS): Utilized AWS EC2 for scalable compute resources and other AWS services to manage and scale the architecture efficiently in the cloud.

## Steps:

### Setting up Heavy Forwarder and configuring it to receive and ingest the DHCP and Snort IDS logs respectively
#### Heavy Forwarder
- Heavy Forwarder will be installed on my local machine (Ubuntu) for this project
- Open Terminal and run the following commands to install Splunk Enterprise
- sudo apt-get update && sudo apt-get upgrade (To upgrade Ubuntu)
- wget -O splunk-9.2.2-d76edf6f0a15-linux-2.6-amd64.deb "https://download.splunk.com/products/splunk/releases/9.2.2/linux/splunk-9.2.2-d76edf6f0a15-linux-2.6-amd64.deb" (To Download Splunk DEB File)
- sudo apt install ./splunk-9.2.2-d76edf6f0a15-linux-2.6-amd64.deb (To install Splunk Enterprise)
- sudo /opt/splunk/bin/splunk start — accept-license (To accept the license before starting Splunk
![Screenshot from 2025-03-04 04-10-56](https://github.com/user-attachments/assets/dff46161-b59b-4420-93f1-5ca144fffa7e)
REF 2 - Accepting License 
- Press and enter Y to accept the licence and proceed with the installation
- Create your username and password for splunk log in
![Screenshot from 2025-03-04 04-16-57](https://github.com/user-attachments/assets/3fe708ef-95f1-483a-8316-e5f912c7b59d)
REF 3 - Creating Username and Password
- sudo /opt/splunk/bin/splunk start (To start Splunk)
![Screenshot from 2025-03-04 04-23-40](https://github.com/user-attachments/assets/a385f040-a235-4c47-a9d2-6fe907b01752)
REF 4 - Sucessfull Splunk Installation
- If you see the above screen then splunk is successfully installed
- sudo /opt/splunk/bin/splunk enable boot-start (To enable boot-start for Splunk)
- For local computer, we can access the splunk's web interface from http://127.0.0.1:8000
- Log in to splunk's web interface and go to Server Settings > General Settings and enable SSL (HTTPS), save and restart splunk when you get the prompt to restart
![Screenshot from 2025-03-04 04-33-07](https://github.com/user-attachments/assets/316dbbe8-aec4-43d3-b7a2-329838217d5b)
REF 5 - Enabling SSL (HTTPS)
- Now you can access splunk from https://127.0.0.1:8000 on your local machine
![Screenshot from 2025-03-04 04-39-33](https://github.com/user-attachments/assets/8beb6b0c-3a63-480b-8fe6-c6af8327b981)
REF 6 - Log IN on SSL enabled splunk web
- From the splunk web page, go to Server Settings > Global Banner, click on Banner Visibility to make it (ON), choose yellow and enter Heavy Forwarder in the message field
![Screenshot from 2025-03-04 21-59-59](https://github.com/user-attachments/assets/7cf5cfd5-0cba-4548-a07f-2b03230c79fd)
REF 7 - Setting up a banner to identify Heavy Forwarder in the cluster architecture
- Now our Heavy Forwarder is ready for configuration

#### Configuring Heavy Forwarder To Receive The DHCP Logs From The Router
- I have configured my wireless router to send the DHCP logs through UDP port 514 to 192.168.0.105 (IP address of Heavy Forwarder)
- Let's configure the Heavy Forwarder to receive the logs from the UDP port 514
- Go to Settings > Data Input and click on + Add New for UDP type
 ![Screenshot from 2025-03-04 22-14-32](https://github.com/user-attachments/assets/91e694d0-c722-4215-97cb-05388dc79b83)
REF 8 - Adding new UDP Data Input
- Enter 514 as the PORT and click NEXT
![Screenshot from 2025-03-05 01-49-12](https://github.com/user-attachments/assets/7b7ca578-c462-4db3-86ae-7e2618581a54)
REF 9 - Selecting UDP and entering the Port Number from where you will receive the data
- Select New and enter "DHCP Logs" as source type and "DHCP Logs from Router"
![Screenshot from 2025-03-05 01-54-50](https://github.com/user-attachments/assets/c40b7a0e-5cd3-4e45-a307-07a9866afa2d)
REF 10 - Creating a new source type and index to for the DHCP logs to be ingested
- Click Next to review the input settings and Next to confirm the settings to create the UDP Input successfully.
![Screenshot from 2025-03-05 02-14-30](https://github.com/user-attachments/assets/614861b5-b9e6-4bb2-8a89-c21009600bed)
REF 11 - UDP Input created successfully
- Click on start searching and you will see the logs coming in as the DHCP logs are updated on the router
![Screenshot from 2025-03-05 02-25-07](https://github.com/user-attachments/assets/6ba85463-d250-4074-b648-10f82cf6ba53)
REF 12 - Searching the logs for the UDP input we just created

#### Installing and Configuring Snort
- Enter the below commands on Terminal
- sudo apt-get install snort -y (To install Snort)
![Screenshot from 2025-03-05 03-05-24](https://github.com/user-attachments/assets/2e0e1abd-8bc1-49ca-8cb4-8d91a58fd9b8)
REF 13 - Configuring Snort
- When you see the above screen, open another terminal and enter the below command to find the range of your IP addresses
- ip addr (To find the IP address and range)
- As my local computer is connected to the wifi router the interface and the IP Address will be as specified in the below image --
![Screenshot from 2025-03-05 03-10-59](https://github.com/user-attachments/assets/d4f86f17-20a6-4fae-8b11-66e42a6ad76e)
REF 14 - Finding the interface name and the range of your IP address
- Switch back to the terminal where you were downloading snort and enter the IP address as 192.168.0.0/24 to configure the Snort
- Press Enter and snort will be installed successfully
- sudo ip link set wlp0s20f3 promisc on (To turn on promisc on the interface)
![Screenshot from 2025-03-05 03-38-20](https://github.com/user-attachments/assets/f6c1c4c8-432b-427a-9634-fbceb53ad19c)
REF 15 - Turning on promisc on the interface
- sudo vim /etc/snort/snort.conf (to edit the snort configuration file)
- scroll down and edit network variable from any to ipvar HOME_NET 192.168.0.0/24
![Screenshot from 2025-03-05 03-46-01](https://github.com/user-attachments/assets/4100ce8a-1c4b-4a7d-a423-00f9ff2fa354)
REF 16 - Editing the network variable
- :wq (save the file)
- Now to test snort we can create a custom rule to trigger an alert
- sudo vim etc/snort/rules/local.rules (Open the local rules file to add custom rules)
- Add the below rules to trigger an alert for ICMP and SSH attempt onto my network
- alert icmp any any -> $HOME_NET any (msg:"Ping Detected!"; sid:100001; rev:1;)
- alert tcp any any -> $HOME_NET 22 (msg:"SSH Authentication Attempt"; sid: 100002; rev: 1;)
![Screenshot from 2025-03-05 04-18-17](https://github.com/user-attachments/assets/7a6aab89-322a-4c28-a167-03ed5451e507)
REF 17 - Adding custom rules on local.rules file
- :wq (save the file)
- Run the below command on the terminal to start the snort in alert mode and output the logs on the terminal's console
-  sudo snort -q -l /var/log/snort -i wlp0s20f3 -A console -c /etc/snort/snort.conf
![Screenshot from 2025-03-05 20-23-20](https://github.com/user-attachments/assets/53a19a1a-8cee-4031-b28d-a8f16f8e2e21)
REF 18 - Running snort in alert mode and output the logs on the console
- Let's ping our IP address from another machine to see if we are getting the alerts
![image (1)](https://github.com/user-attachments/assets/45127b21-ad9b-4db9-b082-f5d540c92c06)
REF 19 - Pinging our IP address from another computer
- On our local machine, we can now see the alerts are being triggered on the terminal as below
![Screenshot from 2025-03-05 20-37-22](https://github.com/user-attachments/assets/a55874b9-6511-4b4e-8572-5ceb413db518)
REF 20 - Successfully receiving the triggered alerts on our terminal
- Run the below command to start snort in alert mode with 'fast' option which writes the logs in the default alert file
- sudo snort -q -l /var/log/snort -i wlp0s20f3 -A fast -c /etc/snort/snort.conf
- The alert file is located in /var/log/snort/ . Open the file to check if the alerts are being recorded.
- sudo vim /var/log/snort/alert
![Screenshot from 2025-03-05 21-06-10](https://github.com/user-attachments/assets/661ae82b-dbf9-468c-b9e4-6b9eae4da2fb)
REF 21 - The alert file which is being updated for every triggered snort alert
- We see that the alert logs are being stored in the alert file and this file will be updated with every triggered alert.

##### NOTES ON SNORT
- Enter "man snort" on the terminal to read the manual for Snort which is really helpful to understand it's options
- We can create and customize our own rules in etc/snort/rules/local.rules file
- If you need any help in creating snort rules, go to https://snorpy.cyb3rs3c.net/ for a snort rules creator
![Screenshot from 2025-03-05 21-18-38](https://github.com/user-attachments/assets/7db036be-2463-4da0-99f1-194803be9015)
REF 22 - SNORPY - A web based snort rule creator

#### Ingesting Snort Alerts in Splunk
- We know all the snort alerts are being logged to /var/log/snort/
- In order to ingest those alerts in Splunk, we can create a data input to monitor and index the above directory
- In splunk web interface, go Settings > Data Inputs and click on "Add New" for "Files and Directories"
![Screenshot from 2025-03-05 21-28-35](https://github.com/user-attachments/assets/093fc5c4-8101-4d27-ab8d-a226f7e9aa4b)
REF 23 - Adding new Data Input under Files and Directories
- Click Browse on File or Directory field and select source as /var/log/snort/ as shown below
![Screenshot from 2025-03-05 21-32-19](https://github.com/user-attachments/assets/98511d0f-04bf-4b7a-8a35-ca7aa33a0110)
REF 24 - Selecting the snort alert file directory
- Click Next and select the source type as "snort" which will be under the drop down option "Network and Security"
- Create a new index "snort_alert" to ingest the snort alert data into this index
![Screenshot from 2025-03-05 21-38-43](https://github.com/user-attachments/assets/ff400a8a-14ae-42ee-aa4d-ce895aecae02)
REF 25 - Selecting the source type and creating a new index for snort alerts
- Click Review to review data input and click Submit
- Click on start searching and select the preset as All time (real-time) to monitor the index in real time
![Screenshot from 2025-03-05 21-46-19](https://github.com/user-attachments/assets/0a57d519-97c6-4d9d-bde2-afbcffe1cfa6)
REF 26 - Searching on splunk for snort alert logs in real time
- Let's try to ping our IP address from another computer and check the real time search on splunk to see if the alert logs are being ingested in real time
![image (2)](https://github.com/user-attachments/assets/685c28c7-18ee-422d-94c1-450565d1ca13)
REF 27 - Pinging our IP address from another computer
![Screenshot from 2025-03-05 21-52-32](https://github.com/user-attachments/assets/93644cea-0d7f-498a-9955-f72f4706628b)
REF 28 - Triggered alerts being logged in splunk in real time

###### The Heavy Forwarder is now configured to receive the DHCP and Snort IDS logs in real time.

### Setting Up AWS EC2 Instances and Splunk Cluster Architecture 
#### Setting Up the indexer cluster on AWS EC2 instances
- To set up an indexer cluster, we atleast need 2 indexers and 1 cluster master (manager node)
- Let's spin up 3 EC2 instances with the below configuration </br>
  Operating System: Ubuntu </br>
  Instance Type: t2.medium </br>
  Security Group: Keep the same security group you select for all instances </br>
  Configure Storage: 30GiB </br>
  Edit The name Of the Instances to Indexer_1, Indexer_2 and Cluster_Master
![Screenshot from 2025-03-06 02-38-34](https://github.com/user-attachments/assets/cb968cbd-170e-4276-8e81-7ec8982be8c3)
REF 29 - Starting EC2 instances on AWS for Indexer Cluster
- As all of the instances are assigned dynamic public IP addresses, we would need static public IP addresses assigned to each of them so that they remain the same even if the instance is restarted
- To assign a static public IP address on AWS, click on Elastic IP's under Network & Security on the options on the left
- Click on Allocate Elastic IP Address and make sure the Network Border Group is set to the same network your instaces is assigned to
![Screenshot from 2025-03-06 02-52-43](https://github.com/user-attachments/assets/27bfb6e2-90d9-4402-863e-3931bb066acf)
REF 30 - Creating Elastic IPs
- Click Allocate and repeat this process until you have 3 elastic IP addresses
![Screenshot from 2025-03-06 02-56-50](https://github.com/user-attachments/assets/bd4e6035-516e-43c6-aa0f-de76327d7099)
REF 31 - Associating Elastic IPs
- Select one of the allocated IP address and click on Actions > Associate Elastic IP Address
- Select the instance "Indexer_1" and click Associate </br>
Repeat this process until "Indexer_2" and "Cluster_Master" have the associated Elastic IPs
![Screenshot from 2025-03-06 03-12-33](https://github.com/user-attachments/assets/0a1f4de5-7cca-46ac-ae49-61cd67abf228)
REF 32 - All 3 Elastic IPs associated with the "Indexer_1" , "Indexer_2" and "Cluster_Master" respectively
- Now let's configure the security group for my local machine to access these instances and also to allow traffic via TCP in between these instances
![Screenshot from 2025-03-07 04-13-44](https://github.com/user-attachments/assets/75fda309-2a2e-46ca-9e6c-00f0e86a233b)
REF 33 - Configuring Security Group in AWS
- SSH into "Indexer_1" , "Indexer_2" and "Cluster_Master" and follow the below steps (these will be the same steps we followed to install Splunk in Heavy Forwarder on our local Ubuntu machine)
- sudo apt-get update && sudo apt-get upgrade (To upgrade Ubuntu)
- wget -O splunk-9.2.2-d76edf6f0a15-linux-2.6-amd64.deb "https://download.splunk.com/products/splunk/releases/9.2.2/linux/splunk-9.2.2-d76edf6f0a15-linux-2.6-amd64.deb" (To Download Splunk DEB File)
- sudo apt install ./splunk-9.2.2-d76edf6f0a15-linux-2.6-amd64.deb (To install Splunk Enterprise)
- sudo /opt/splunk/bin/splunk start — accept-license (To accept the license before starting Splunk
- Press and enter Y to accept the licence and proceed with the installation
- Create your username and password for splunk log in
- sudo /opt/splunk/bin/splunk start (To start Splunk)
- sudo /opt/splunk/bin/splunk enable boot-start (To enable boot-start for Splunk)
- Now let's note down the IP addresses of our AWS instances --

| Instance Name  | Elastic Public IP | Private IP |
| ------------- | ------------- | ------------ |
| Indexer_1  | 13.233.221.135  | 172.31.38.143 |
| Indexer_2  | 3.110.22.171 | 172.31.32.159 |
| Cluster_Master  | 3.111.202.177 | 172.31.47.184 |

- We can now access splunk web installed on the above instances through by http://Elastic Public IP:8000
- After enabling SSL (HTTPS) on all of the instances, here are the splunk web details that we can access through our local machine --

| Instance Name  | Splunk Web Address |
| ------------- | ------------- |
| Indexer_1  | https://13.233.221.135:8000  |
| Indexer_2  | https://3.110.22.171:8000 |
| Cluster_Master  | https://3.111.202.177:8000 |

- Log in to splunk on each of the instance and display their intance names on each of them respectively through global banners --
![Screenshot from 2025-03-07 06-31-52](https://github.com/user-attachments/assets/b47ade66-b0f9-4791-8b32-92d554b87c56)
REF 34 - Indexer_1 Splunk Web
![Screenshot from 2025-03-07 06-34-12](https://github.com/user-attachments/assets/704653fb-e30b-41c8-9c6a-0e7458bc752e)
REF 35 - Indexer_2 Splunk Web
![Screenshot from 2025-03-07 06-34-34](https://github.com/user-attachments/assets/9bc28789-2d82-40e6-b094-0120710241d8)
REF 36 - Cluster_Master Splunk Web
- Now on Cluster_Master splunk web, click settings > Indexer Clustering and click on Enable Indexer Clustering
![Screenshot from 2025-03-07 06-44-51](https://github.com/user-attachments/assets/fc4ca0f0-ee30-4205-8c28-e9d786946a42)
REF 37 - Selecting Cluster_Master to be configured as Manager Node (Cluster Master)
- Select Manager Node and click next
- Keep Replication Factor and Search Factor as 2
![Screenshot from 2025-03-07 06-46-57](https://github.com/user-attachments/assets/169cffed-9f97-4509-812e-d22b699831b9)
REF 38 - Configuring Cluster Master
- Click on Restart Now
- Log in again to Cluster_Master splunk web and you will see below --
![Screenshot from 2025-03-07 22-33-16](https://github.com/user-attachments/assets/45c7d260-5171-4bb9-b917-912e3fdcfb10)
REF 39 - Cluster Master Configured Successfully
- Now log in to Indexer_1 Splunk Web and go to Settings > Indexer Clustering
- Click on Enable Indexer Clustering and select Peer Node and click Next
![Screenshot from 2025-03-07 22-37-11](https://github.com/user-attachments/assets/7b46578e-6c78-48b5-bfe6-a2a9be24be6a)
REF 40 - Enabling Indexer Clustering as a Peer Node for Indexer_1
- Enter the private IP address of the Cluster_Master instance as the manager url (https://172.31.47.184:8089)
- Enter 8080 as the Peer replication port
###### Note: 8089 is the management port and 8080 is the replication port
![Screenshot from 2025-03-07 22-39-44](https://github.com/user-attachments/assets/2edc8184-918c-4a3c-976a-b4654f095c10)
REF 41 - Configuring peer node (Indexer in cluster)
- Click Enable peer node and then click on restart now
- Now let's log in to Indexer_2 splunk web and repeat the same process to set up indexer clustering as a Peer Node
- After we enabled Indexer_2 as peer node and restarted it let's log in back to Cluster_Master splunk web to check the status of the cluster
![Screenshot from 2025-03-07 23-04-55](https://github.com/user-attachments/assets/ceba6380-0c67-46df-845c-30ceda4eb3fc)
REF 42 - Manager Node (Cluster_Master) indicating the cluster is successfully configured
- You can see the private IP addresses of "Indexer_1" and "Indexer_2" under peer name (that means both the indexers are successfully configured in this indexer cluster)
- You can also note that the cluster is healthy if you see "All Data is Searchable" , "Search Factor is Met" and "Replication Factor is Met"

#### Setting Up the search head cluster on AWS EC2 instances

- To set up an search head cluster, we atleast need 1 search head and 1 search head (Captain)
- Let's spin up 2 more EC2 instances with the below configuration </br>
  Operating System: Ubuntu </br>
  Instance Type: t2.medium </br>
  Security Group: Keep the same security group you select for all instances </br>
  Configure Storage: 30GiB </br>
  Edit The name Of the Instances to SearchHead_1 and SearchHead_Captain
![Screenshot from 2025-03-07 23-32-39](https://github.com/user-attachments/assets/d450f8d5-79a1-438f-b2de-4aaac507419e)
REF 43 - Starting EC2 Instances for Search Head Cluster
- SSH into "SearchHead_1" and "SearchHead_Captain" and follow the below steps (these will be the same steps we followed to install Splunk in Heavy Forwarder on our local Ubuntu machine)
- sudo apt-get update && sudo apt-get upgrade (To upgrade Ubuntu)
- wget -O splunk-9.2.2-d76edf6f0a15-linux-2.6-amd64.deb "https://download.splunk.com/products/splunk/releases/9.2.2/linux/splunk-9.2.2-d76edf6f0a15-linux-2.6-amd64.deb" (To Download Splunk DEB File)
- sudo apt install ./splunk-9.2.2-d76edf6f0a15-linux-2.6-amd64.deb (To install Splunk Enterprise)
- sudo /opt/splunk/bin/splunk start — accept-license (To accept the license before starting Splunk
- Press and enter Y to accept the licence and proceed with the installation
- Create your username and password for splunk log in
- sudo /opt/splunk/bin/splunk start (To start Splunk)
- sudo /opt/splunk/bin/splunk enable boot-start (To enable boot-start for Splunk)
- Now let's note down the IP addressess of all our AWS Instances including search heads

| Instance Name  | Public IP | Private IP |
| ------------- | ------------- | ------------ |
| SearchHead_1 | 13.232.83.97 | 172.31.41.162 |
| SearchHead_Captain  | 13.232.60.122 | 172.31.34.86 |

###### Please note the public IP will change whenever you restart the EC2 Instance

- We can now access splunk web installed on the above instances through by http://Public IP:8000
- Enable SSL (HTTPS) on the above insances
- Log in to splunk on each of the instance and display their intance names on each of them respectively through global banners
![Screenshot from 2025-03-08 00-04-31](https://github.com/user-attachments/assets/25662b81-b220-467d-bf7e-3147e1f40925)
REF 44 - SearchHead_1 Splunk Web
![Screenshot from 2025-03-08 00-04-51](https://github.com/user-attachments/assets/3ffd6fae-447a-427c-aa38-6d8890749515)
REF 45 - SearchHead_Captain
- Now on SearchHead_1 splunk web, click Settings > Indexer Clustering and click Enable Indexer Clustering
- Select Search Head Node and click Next
![Screenshot from 2025-03-08 00-07-55](https://github.com/user-attachments/assets/14e2b942-ee39-4431-81ed-d6d761590fdd)
REF 46 - Selecting Search Head Node
- Enter the private IP address of the Cluster_Master instance as the manager url (https://172.31.47.184:8089)
- Click Enable search head node
- Click Restart Now
- Repeat the same process on SearchHead_Captain splunk web and restart it
- Log in back to the Cluster_Master splunk web and click on Settings > Indexer Clustering
- You can see the private IPs of SearchHead_1 and SearchHead_Captain along with the private IP of the Cluster_Master under Search Head Name
![Screenshot from 2025-03-08 00-17-44](https://github.com/user-attachments/assets/bd908de6-3ec3-4b1d-bcc3-7c28aa34cf54)
REF 47 - Search Heads in Cluster_Master (Master Node)
- Our cluster architecture is now completely up and running and is ready for the data to be received by our heavy forwarder

### Forwarding The Data Into Our Cluster Through Heavy Forwarder

#### Identifying The Indexes we created in Heavy Forwarder
- For our data to be forwarded correctly in the Cluster, the indexes which we have created for the data to be ingested in Heavy Forwarder should also be created in all the indexers in the cluster
- We can do this by copying indexes.conf configuration in the heavy forwarder
- First we need to check the app names in which we have created our indexes
- Log in on Heavy Forwarder's (Our local Machine's) Splunk Web and click on Settings > Indexes
![Screenshot from 2025-03-08 00-40-52](https://github.com/user-attachments/assets/25dd01a4-328f-497a-ad68-eae4fbf332ce)
REF 48 - Identifying indexes we created while ingesting data in Heavy Forwarder
- We can see that we have created the indexes "dhcp_logs" and "snort_alert" in the Heavy Forwarder
- Their indexes.conf file will be located under their respective app folders (alert_logevent and 	snortalert)
- On your local machine's terminal run the following commands to copy the indexes.conf configuration
- sudo vim /opt/splunk/etc/apps/alert_logevent/local/indexes.conf
- Copy the configuration and paste it on a note pad
- sudo vim /opt/splunk/etc/apps/snortalert/local/indexes.conf
- Copy the configuration and paste it on a note pad
- Here are the configuration that we have copied for both the indexes </br>

[dhcp_logs] </br>
coldPath = $SPLUNK_DB/dhcp_logs/colddb </br>
homePath = $SPLUNK_DB/dhcp_logs/db </br>
maxTotalDataSizeMB = 512000 </br>
thawedPath = $SPLUNK_DB/dhcp_logs/thaweddb </br> </br>

[snort_alert] </br>
coldPath = $SPLUNK_DB/snort_alert/colddb </br>
homePath = $SPLUNK_DB/snort_alert/db </br>
maxTotalDataSizeMB = 512000 </br>
thawedPath = $SPLUNK_DB/snort_alert/thaweddb </br>

#### Creating The Above Indexes in The Clustered Indexers Through Cluster Master
- SSH into Cluster Master EC2 instance
- cd /opt/splunk/etc/master-apps/_cluster/local
- sudo vi indexes.conf (Creating a indexes.conf file)
- Paste the indexes

![Screenshot from 2025-03-10 21-04-56](https://github.com/user-attachments/assets/83c7d4de-3ba7-4cae-aad6-2df48b64e456) </br>
REF 49 - Pasting the indexes and it's configuration in indexes.conf
- :wq (Save the file and exit)

#### Pushing the indexes through Cluster_Master Splunk Web
- Go to Settings > Indexer Clustering
- Click on Edit > Configuration Bundle Actions
![Screenshot from 2025-03-10 21-10-54](https://github.com/user-attachments/assets/67f987fc-527a-4b94-a574-b77f59740135) </br>
REF 50 - Configuration Bundle Actions
- Click on Validate and Check Restart
- Check if the validation is successful and restart is not required
![Screenshot from 2025-03-10 21-12-28](https://github.com/user-attachments/assets/6b569b65-4c9d-4045-897b-dc639b7b3212) </br>
REF 51 - Validation is successful and restart is not required
- Click on Push to push the indexes into both the 'Indexer_1' and 'Indexer_2'
- After push is successful, all the indexes will be pushed to all the indexers in the cluster
![Screenshot from 2025-03-10 21-15-11](https://github.com/user-attachments/assets/4a1ef1e6-dc5b-4420-b3f2-580395c58363) </br>
REF 52 - Push is Successful


