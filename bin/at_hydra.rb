require 'rubygems'
require 'net/sftp'
require 'net/ssh/gateway'
require 'socket'
require 'fileutils'
require 'timeout'

#
# at_hydra.rb -d -c -h hosts_syfq.txt -f filter -u root -p password -k -l logs.txt -s services.txt
#
# -d: drop server script on all hosts
# -c: connect to all hosts and download log entries
# -h: list of hosts
# -f: filter
# -l: log list
# -s: service list
# -k: kill
#
#

$stdout.sync = true

@args = ['-d','-c','-h','-f','-k','-l','-s']
@options = {}
@hosts = {}

$hydra_port = 33033
$hydra_script = 'bin/at_server.pl'

$almp = { :at_msg       => 'AT_MSG',      # start of a log entry message
          :at_end       => 'AT_END',      # end of a message (filter, log entry or connection options)
          :at_bye       => 'AT_BYE',      # on client disconnect
          :at_term      => 'AT_TERM',     # on client disconnect with server termination
          :at_logs      => 'AT_LOGS',     # log paths
          :at_filter    => 'AT_FILTER',   # start of filter message
          :at_services  => 'AT_SERVICES', # service names
}


def set_int_exit
  trap("INT") {
    exit
  }
end
#
#def set_int_continue
#  trap("INT") {
#  }
#end


#
# print_usage_and_exit
#
def print_usage_and_exit
  puts "\nUsage: #{$0} -[d,c,k] -h <hosts file> -f <filter> -l <log list> -s <service list>\n\n" <<
        "\t-d: drop server script on all hosts\n" <<
        "\t-c: connect to all hosts and download log entries\n" \
        "\t-k: kill server on all hosts\n"
  exit 1
end

#
# parse_cmd_args
#
def parse_cmd_args
  @args.each {|a| @options[a] = ARGV.index(a)}
  if @options['-h']
    @hosts_file = ARGV[@options['-h']+1]
  end
  if @options['-f']
    @filter_file = ARGV[@options['-f']+1]
  end
  if @options['-l']
    @logpaths_file = ARGV[@options['-l']+1]
  end
  if @options['-s']
    @service_file = ARGV[@options['-s']+1]
  end
end


#
# read_hosts
#
def read_hosts
  keys = [:ip, :port, :user, :password]
  File.open(@hosts_file,'r') do |f|
    f.each do |l|
      l.sub!(/#.*/,'')
      l.strip!
      next if l.empty?
      a = l.split
      @hosts[a[0]] = Hash[*keys.zip(a[1..-1]).flatten] # keys[0] => a[1], keys[1] => a[2], ...
    end
  end
end

#
# read_config
#
def read_config(fpath,name)
  # FIXME: newline artifacts after stripping comments
  config = File.open(fpath, 'r') { |f| f.read }
  config.gsub!(/\r/,"\n")
  config.gsub!(/#.*$/,'')
  config.gsub!(/^(\n|\s)*$/,'')
  puts "\nUsing #{name} (#{fpath}): \n"
  config.split(/\n/).each {|l| puts "  #{l}\n"}
  puts "\n"
  config
end


#
# drop_server
#
def drop_server
  
  set_int_exit
  
  puts "\nDropping server on all hosts and opening remote port #{$hydra_port}:\n\n"
  
  @hosts.sort.each do |hostname,host|
    #
    # upload & execute script
    #
    begin
      print "  #{hostname} (#{host[:user]}@#{host[:ip]}:#{host[:port]}) "
      Net::SSH.start(host[:ip], host[:user], :port => host[:port], :password => host[:password], :paranoid => false) do |ssh|
        ssh.sftp.upload!($hydra_script, 'at_server.pl')
        res = ssh.exec!("perl at_server.pl; rm at_server.pl")
        if res.nil?
          print "\tOK"
        else
          print "\tFAILED\n#{res}"
        end
      end
    rescue
      print "error"
      #puts "error: #{ex.message}"
    end
    print "\n"
  end
  puts "\n"
end

#
# connect_client
#
def connect_client(ip, port)
  sockaddr = Socket.pack_sockaddr_in(port, ip)
  socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
  # set recv timeout to 1 sec (workaround for async sockets)
  socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [1, 0].pack("i,i"))
  180.times do
    if socket.connect(sockaddr) == 0
      return socket
    end
    sleep 1
  end
  nil
end


#
# send_message
#
def send_message(s,msg)
  s.write("#{msg}\n")
end


#
# disconnect_client
#
def disconnect_client(s)
  send_message(s,$almp[:at_bye])
  s.close
end


#
# send_filter
#
def send_filter(s)
  send_message(s,$almp[:at_filter])
  send_message(s,@filter)
  send_message(s,$almp[:at_end])
end


#
# send_logpaths
#
def send_logpaths(s)
  send_message(s,$almp[:at_logs])
  send_message(s,@logpaths)
  send_message(s,$almp[:at_end])
end


#
# send_services
#
def send_services(s)
  send_message(s,$almp[:at_services])
  send_message(s,@services)
  send_message(s,$almp[:at_end])
end


#
# send_config
#
def send_config(s)
  # send filter
  if @options['-f'] && @filter
    send_filter(s)
  end
  
  # send log paths
  if @options['-l'] && @logpaths
    send_logpaths(s)
  end
  
  # send service list
  if @options['s'] && @services
    send_services(s)
  end
end

#
# print_hax0r
#
def print_hax0r(str)
  str.split(//).each do |ch|
    print ch
    sleep 0.015
  end
end

#
# connect_tentacles
#
def connect_tentacles
  tentacles = {}
  FileUtils.mkdir_p "./log"
  
  puts "\nOpening tunnels and connecting to hosts (#{@hosts_file}):\n\n"
  
  @hosts.sort.each do |hostname,host|
    begin
      print "  #{hostname} "
      
      socket = nil
      gateway = nil
      
      timeout(60) do
        # create a tunnel L<auto port>:R33033
        gateway = Net::SSH::Gateway.new(  host[:ip], host[:user],
                                          :port     => host[:port],
                                          :password => host[:password],
                                          :paranoid => false)
  
        @hosts[hostname][:lport] = lport = gateway.open('localhost',$hydra_port)
  
        socket = connect_client('127.0.0.1',lport)
        if socket
          print_hax0r "L#{lport}:R#{$hydra_port}\n"
        else
          next
        end
      end
      
      # open local log file
      f = File.open("./log/#{hostname}.log", 'w')
      f.sync = true
      
      tentacles[hostname] = {:socket=>socket, :output=>f, :state=>nil, :gateway=>gateway}
    rescue Timeout::Error
      puts "timeout"
    rescue => ex
      puts "error"
      #puts "#{ex.message}"
    end
  end
  
  #
  # handle CTRL+C
  #
  trap("INT") {
    disconnect_tentacles(tentacles)
    puts "\n"
    return 0
  }
  
  puts "\nTo exit press Ctrl+C\n\n"
  
  #
  # send config and keep track of sockets
  #
  sockets={}
  tentacles.each do |k,v|
    begin
      send_config(v[:socket])
      sockets[v[:socket]]=k
    rescue Errno::ECONNABORTED
      puts "#{k}: failed to send config!"
      tentacles.delete(k)
    end
  end
  
  while 1
    if sel=select(sockets.keys,nil,nil,1)
      sel[0].each do |socket|
        
        hostname = sockets[socket]
        
        #
        # get data from server
        #
        data = socket.recv(8192)
        
        if data.empty?
          print "  reconnecting to #{hostname}..."
          #
          # disconnected from server
          #
          olds = socket
          socket.close
          if socket = connect_client('127.0.0.1',@hosts[hostname][:lport])
            tentacles[hostname][:socket] = socket
            sockets.delete(olds)
            sockets[socket] = hostname
            
            send_config(socket)
            print " OK\n"
          else
            print " FAILED\n"
          end
          next
        else
          # FIXME: For now there are no control messages. For very verbous logs
          #        line-based processing is too CPU expensive. So simply dump all received data.
          tentacles[hostname][:output]<<data
          tentacles[hostname][:output].flush
        end
      end
    end
  end
end


#
# disconnect_tentacles
#
def disconnect_tentacles(tentacles)
  set_int_exit
  puts "\nPlease wait, disconnecting...\n"
  msg = ''
  # if -k is also given as argument send term msg to server
  if @options['-k']
    msg = $almp[:at_term]
    puts "\nkilling remote server on all hosts...\n"
  else
    msg = $almp[:at_bye]
  end
  tentacles.each do |k,v|
    begin
      send_message(v[:socket],msg)
      v[:socket].close
      v[:output].close
      #v[:gateway].shutdown! # gateway will take care of itself
    rescue => ex
      #puts "error: #{ex.message}"
    end
  end
end


#
# kill_server
#
def kill_server
  
  puts "\nKilling server:\n\n"
  
  @hosts.sort.each do |hostname,host|
    #
    # kill remote server
    #
    puts "\t#{hostname}"
    begin
      Net::SSH.start(host[:ip], host[:user], :port => host[:port], :password => host[:password], :paranoid => false) do |ssh|
        ssh.exec!("kill -2 `cat /home/.at_server 2>/dev/null` 2>/dev/null")
      end
    rescue => ex
      puts "error"
      #puts "error: #{ex.message}"
    end
  end
  puts "\n"
  
end



if ARGV.size==0
  print_usage_and_exit
end


parse_cmd_args


if @options['-h']
  #
  # read hosts
  #
  if @hosts_file
    read_hosts
  else
    print_usage_and_exit
  end
end

if @options['-d']
  #
  # drop server
  #
  if @hosts_file
    drop_server
  else
    print_usage_and_exit
  end
end

if @options['-f']
  #
  # read filter
  #
  if @filter_file
    @filter = read_config(@filter_file,'filter')
  else
    print_usage_and_exit
  end
end

if @options['-l']
  #
  # read log paths
  #
  if @logpaths_file
    @logpaths = read_config(@logpaths_file,'log paths')
  else
    print_usage_and_exit
  end
end

if @options['-s']
  #
  # read service names
  #
  if @services_file
    @services = read_config(@services_file,'service name patterns')
  else
    print_usage_and_exit
  end
end


if @options['-c']
  #
  # connect clients
  #
  connect_tentacles
end


if @options['-k'] && !@options['-c']
  #
  # kill server
  #
  if @hosts_file
    kill_server
  else
    print_usage_and_exit
  end
end
