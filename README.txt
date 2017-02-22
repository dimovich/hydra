--==$$  H Y D R A  $$==--
the log monitoring monster
==========================


================
   THE BASICS
================


Run 'CONNECT.bat' to start receiving log updates. That's all you need most of the times. The logs will be saved in 'Hydra\log' folder.

If the Hydra server is not running on remote hosts then run 'drop.bat'. If you want to kill the Hydra server on all remote hosts then run 'kill.bat'.





================
  THE HARDCORE
================

at_hydra.rb -[d,c,k] -h <hosts file> -f <filter> -l <log paths>

 -d: drop server script on all hosts
 -c: connect to all hosts and download log entries
 -k: kill server on all hosts
 -h: list of hosts
 -f: filter
 -l: log paths list


EXAMPLES:

1)
at_hydra.rb -d -h hosts.txt

This will drop the server on remote hosts.


2)
at_hydra.rb -c -h hosts.txt -f filter.txt -l logpaths.txt

Connect to remote server on all hosts and download log entries based on filter rules.


3)
at_hydra.rb -k -h hosts.txt -u root -p SecretPass

Kill remote server on all hosts.


4)
at_hydra.rb -d -c -k -h hosts.txt -f filter.txt -l logpaths.txt

This will drop the server on remote hosts, connect clients and start receiving log data. The remote server will be killed after the client connections have terminated.
