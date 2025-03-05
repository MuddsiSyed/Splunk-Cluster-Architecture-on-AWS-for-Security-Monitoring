# Splunk Cluster Architecture on AWS for Security Monitoring

## Objective:

The goal of this project is to design and implement a scalable Splunk Cluster Architecture hosted on AWS for centralized log management and real-time security monitoring. This system will ingest and process network security alerts from Snort IDS and DHCP logs from a Wi-Fi router. By leveraging the power of AWS infrastructure, this setup aims to provide robust and fault-tolerant data collection, analysis, and visualization capabilities, enhancing threat detection and network performance monitoring.



![Splunk Clustered Architecture Black](https://github.com/user-attachments/assets/cd2c503a-9cfc-4063-95f6-6d599d5105a1)
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

###### NOTES ON SNORT
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
#### Setting Up the indexer clusters on AWS EC2 instances
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
- Select one of the allocated IP address and click on Actions > Associate Elastic IP Address
- Select the instance "Indexer_1" and click Associate </br>
Repeat this process until "Indexer_2" and "Cluster_Master" have the associated Elastic IPs







