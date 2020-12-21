---
title: " ELK and Filebeat setup and installation on Ubuntu 18.04 with Cyseca.log and Linux Syslog"
date: "2020-03-18"
layout: single
tags:
- ELK
categories:
- Blog-post
---

There is two part of setup. First for Cyseca.log. Second for Linux Syslog.


## Install software requirement

```
$ sudo apt install apt-transport-https wget curl
```

# Syslog-ng

## This part is for Cyseca logging using Syslog-ng

We need to feed our Syslog server with cyseca.log from AWL server, so we need to configure our syslog-ng to collect the log.

a. In ELK/SIEM server, install syslog-ng first

```
$ sudo apt install syslog-ng
```

b. Copy original configuration to ``.bak`` to backup original conf file (in case we messed up). 

```
$ sudo cp /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/syslog-ng.conf.bak
```

c. Edit config file of syslog-ng

```
$ sudo nano /etc/syslog-ng/syslog-ng.conf
```

Uncomment this line in "Sources" part

```
########################
# Sources
########################
# This is the default behavior of sysklogd package
# Logs may come from unix stream, but not from another machine.
#
#source s_src {
#       system();
#       internal();
#};
```

Edit this line to this
```
# If you wish to get logs from remote machine you should uncomment
# this and comment the above source line.
#
source net { udp(); };
#source s_net { tcp(ip(127.0.0.1) port(1000)); };
```

Scrolling to "destination" part, add this line
```
########################
# Destinations
########################
# First some standard logfile
#
destination remote { file("/var/log/cyseca.log"); };
```

Scrolling again to the "Log paths". 

Comment those lines that start with ``log { source(s_src) blablabla `` to avoid error 

and add ``log { source(net); destination(remote); };`` like example above.

```
log { source(net); destination(remote); };
#log { source(tcp_s); destination(cyseca); };
#log { source(s_src); filter(f_auth); destination(d_auth); };
#log { source(s_src); filter(f_cron); destination(d_cron); };
#log { source(s_src); filter(f_daemon); destination(d_daemon); };
#log { source(s_src); filter(f_kern); destination(d_kern); };
#log { source(s_src); filter(f_lpr); destination(d_lpr); };                                                                                                                                                        #log { source(s_src); filter(f_syslog3); destination(d_syslog); };
#log { source(s_src); filter(f_user); destination(d_user); };
#log { source(s_src); filter(f_uucp); destination(d_uucp); };
.
.
.
# till the last of log { source(s_src) blablabla
```

Save the conf file.

d. Restart syslog-ng and check if our syslog port is up or not.

```
$ sudo systemctl restart syslog-ng
$ sudo netstat -antup | grep -i syslog-ng
udp        0      0 0.0.0.0:514       0.0.0.0:*        7534/syslog-ng
```

e. In Cyseca Dashboard. Update the logging configuration like below:-

![syslog config](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/syslog.PNG)

f. Try to execute some executables that Cyseca blocked and see the log at ``cyseca.log`` using 

```
$ sudo cat /var/log/cyseca.log
``` 

If the file doesnt exist, try to repeat step d - f again.

# Configuring Java

Follow this website: https://www.hostinger.my/tutorials/install-java-ubuntu

```
sudo apt-get update && apt-get upgrade
sudo add-apt-repository ppa:linuxuprising/java
sudo apt-get update
sudo apt-get install oracle-java14-installer
```

# ELK Things~

## Install ELK in one bash script

We gonna use ELK version 6.x cause I've trouble with version 7.x.

```
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
sudo apt-get update
sudo apt-get install elasticsearch -y
sudo apt-get install kibana -y
sudo apt-get install logstash -y
```

## Configuring Elasticsearch

Modify *elasticsearch.yml* file:

```
$ sudo nano /etc/elasticsearch/elasticsearch.yml
```

Uncomment *network.host* and *http.port* and do some changes and addition. Following configuration should be added:
```
network.host: 0.0.0.0
transport.tcp.port: 9300
http.port: 9200
```

Check java home

```
$ sudo echo $JAVA_HOME
```

Edit and uncomment this part in ``/etc/default/elasticsearch`` to

```
$ sudo nano /etc/default/elasticsearch
```
```
JAVA_HOME=/usr/lib/jvm/java-14-oracle
```

Enable and start elastic search:

```
$ sudo systemctl enable elasticsearch.service && sudo systemctl start elasticsearch.service && sudo systemctl status elasticsearch
```

Check installation

```
$ curl localhost:9200/?pretty
```

## Configuring Kibana

Modify Kibana settings:

```
$ sudo nano /etc/kibana/kibana.yml
```

Uncomment following lines:
```
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.url: "http://localhost:9200"
```

Enable it on boot and start Kibana service:

```
$ sudo systemctl enable kibana.service && sudo systemctl start kibana.service && sudo systemctl status kibana.service
```

Go to this url *localhost:5601* to view Kibana dashboard

## Configuring Logstash

To load logstash beat create the below config file and insert below lines:

```
$ sudo nano /etc/logstash/conf.d/logstash.conf
```

```
input {
        beats { ##beats will ship our cyseca.log to logstash
        port => "5044"
    }
}

filter {
  grok {
   match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IP:IP_AWL} AWLServer\[%{NUMBER:AWL_SERVER}\]: info: \|type:\"%{WORD:Type}\"\|client=%{NUMBER:CLIENT}\|ip=::ffff:%{IPV4:IP_CLIENT}\|size=%{NUMBER:SIZE}\|sha256=%{WORD:SHA256}\|path=\"%{WINPATH:PATH}\"\|md5=%{WORD:MD5}\|sha1=%{WORD:SHA1}\|msg=\|" }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "logstash-cyseca-%{+YYYY.MM.dd}"
  }
}
```

Let’s enable Logstash on boot:

```
$ sudo systemctl enable logstash.service
```

To check for error configuration, run command:

```
$ sudo /usr/share/logstash/bin/logstash -f logstash.conf --config.reload.automatic
```

Don't start logstash yet. We gonna setup filebeat first.

## Installing and Configuring Filebeat

Filebeat -> Logstash (to parse our log) -> Elastic -> Kibana

To install filebeat:

```
$ curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-6.8.7-amd64.deb && sudo dpkg -i filebeat-6.8.7-amd64.deb
```

Now lets make changes in below configuration file

```
$ sudo nano /etc/filebeat/filebeat.yml
```

In the configuration file go to Filebeat Section change false to true as shown below :

```
#=========================== Filebeat inputs =============================
# Change to true to enable this input configuration.
  enabled: true                            #  (change false to true)
  paths:
    - /var/log/cyseca.log
```
In the configuration file go to Kibana Section as shown below:
```
#============================== Kibana =====================================
# uncomment the host and change "localhost to IP"
host: "<IP of server>:5601"
```

In the configuration file got ElasticSearch Section as shown below:
```
#-------------------------- Elasticsearch output ------------------------------
# comment the output and hosts section
#output.elasticsearch:
#hosts: ["<IP of server>:9200"]
```

In the configuration file got ElasticSearch Section as shown below:
```
#----------------------------- Logstash output --------------------------------
# uncomment the host and output. Set the host to local
output.logstash:
  # The Logstash hosts
  hosts: ["localhost:5044"]
```

We will start and enable Filebeat:
The setup command loads the Kibana dashboards. If the dashboards are already set up, omit this command.

```
$ sudo filebeat setup
$ sudo service filebeat start #or restart if you have start before
```

## To start all service (Run this command when you've done config)
```
$ sudo systemctl start elasticsearch.service && sudo systemctl start kibana.service && sudo systemctl start logstash.service && sudo systemctl start filebeat
```

## Display log on Kibana

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/logstash1.PNG)
![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/logstash2.PNG)
![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/logstash3.PNG)
![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/logstash4.PNG)


---

# Filebeat setup and installation for Linux Syslog log.

This step, doesnt require logstash. Because we directly connect logstash to elastic

Filebeat -> Elastic -> Kibana

As example we gonna setup syslog logging.

Go to Kibana _home_ > _Logging_ > _add log data_ > _system logs_. And follow the steps for _DEB_.

## Install and Configure Filebeat

To install filebeat:

```
$ curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-6.8.7-amd64.deb && sudo dpkg -i filebeat-6.8.7-amd64.deb
```

Now lets make changes in below configuration file

```
$ sudo nano /etc/filebeat/filebeat.yml
```

In the configuration file go to Filebeat Section change false to true as shown below :
```
#=========================== Filebeat inputs =============================
# Change to true to enable this input configuration.
  enabled: true                            #  (change false to true)
  paths:
    - /var/log/syslog
```

In the configuration file go to Kibana Section as shown below:
```
#============================== Kibana =====================================
# uncomment the host and change "localhost to IP"
host: "<IP of server>:5601"
```

In the configuration file got ElasticSearch Section as shown below:
```
#-------------------------- Elasticsearch output ------------------------------
# uncommnet the hosts section
hosts: ["<IP of server>:9200"]
```

To enable Filebeat modules, we need to edit the “filebeat.reference.yml” configuration file:

```
$ sudo nano /etc/filebeat/filebeat.reference.yml
```

We will enable the syslog system module for Filebeat:

```
module: system
# Syslog
syslog:
enabled: true
```

Enable and configure the system module
```
$ sudo filebeat modules enable system
```
Edit ``/etc/filebeat/modules.d/system.yml``

```
- module: system
  syslog:
    enabled: true
    var.paths: ["/var/log/syslog*"]
  auth:
    enabled: true
    var.paths: ["/var/log/auth.log*"]
```

We will start and enable Filebeat:
The setup command loads the Kibana dashboards. If the dashboards are already set up, omit this command.

```
$ sudo filebeat setup
$ sudo service filebeat start #or restart if you have start before
```
Click "Check data" to ensure elastic have fetch our syslog. Now go to dashboard panel. Restart and set Time Range to "Today" 






---

You're good to go now! ❤️

Reference:
1. [https://www.fosslinux.com/6084/how-to-install-elk-stack-on-ubuntu-18-04.htm](https://www.fosslinux.com/6084/how-to-install-elk-stack-on-ubuntu-18-04.htm)
2. [https://www.linuxcloudvps.com/blog/how-to-install-elk-stack-on-ubuntu-18-04/](https://www.linuxcloudvps.com/blog/how-to-install-elk-stack-on-ubuntu-18-04/)
3. [https://www.fosstechnix.com/install-elk-stack-on-ubuntu/](https://www.fosstechnix.com/install-elk-stack-on-ubuntu/)
4. [https://linuxconfig.org/install-elk-on-ubuntu-18-04-bionic-beaver-linux](https://linuxconfig.org/install-elk-on-ubuntu-18-04-bionic-beaver-linux)
5. [https://www.lahilabs.com/2020/01/02/how-to-install-elk-siem-for-beginners-complete-guide/](https://www.lahilabs.com/2020/01/02/how-to-install-elk-siem-for-beginners-complete-guide/)
6. [https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-ubuntu-14-04](https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-ubuntu-14-04)
7. [https://raymii.org/s/tutorials/Syslog_config_for_remote_logservers_for_syslog-ng_and_rsyslog_client_server.html](https://raymii.org/s/tutorials/Syslog_config_for_remote_logservers_for_syslog-ng_and_rsyslog_client_server.html)

Credit:
1. Elasticsearch guy who taught me a lot about Elastic and Kibana [@badrul_aminnn](https://twitter.com/badrul_aminnn)
