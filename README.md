# Splunk Cluster Architecture on AWS for Security Monitoring

## Objective:

The goal of this project is to design and implement a scalable Splunk Cluster Architecture hosted on AWS for centralized log management and real-time security monitoring. This system will ingest and process network security alerts from Snort IDS and DHCP logs from a Wi-Fi router. By leveraging the power of AWS infrastructure, this setup aims to provide robust and fault-tolerant data collection, analysis, and visualization capabilities, enhancing threat detection and network performance monitoring.



![Splunk Clustered Architecture Black](https://github.com/user-attachments/assets/cd2c503a-9cfc-4063-95f6-6d599d5105a1)

REF 1 - SPLUNK CLUSTERED ARCHITECTURE


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

### Setting up Splunk Clustered Architecture on Local Machine and AWS EC2 Instances
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

#### Configuring Heavy Forwarder To Receive and Ingest The Data
- I have configured my wireless router to send the DHCP logs through UDP port 514 to 192.168.0.105 (IP address of Heavy Forwarder)
- Let's configure the Heavy Forwarder to receive the logs from the UDP port 514
- Go to Settings > Data Input and click on + Add New for UDP type
 ![Screenshot from 2025-03-04 22-14-32](https://github.com/user-attachments/assets/91e694d0-c722-4215-97cb-05388dc79b83)

This project will provide a comprehensive understanding of both security monitoring and cloud-based architecture, allowing for the development of a flexible and scalable solution for real-time network analysis and threat detection.
