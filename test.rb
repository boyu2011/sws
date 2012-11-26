#
# This script is responsible for testing sws app.
#
#					Bo Yu ( boyu2011@gmail.com )
#

require 'net/http'

app = "./sws"
#ip = "127.0.0.1"
ip = "::1"
port = 8082
dir = "."

pid = fork do
	# child
	cmd = "#{app} -i #{ip} -p #{port} #{dir}"
	puts cmd
	exec cmd + " > /dev/null"
end

# parent
sleep 2

#
# test case 1
#
uri = "/index.html"
puts "Starting visit #{ip}:#{port}#{uri}"
h = Net::HTTP.new(ip, port )
response =  h.get(uri, nil)
puts response.message

#
# test case 2
#
uri = '/files'
puts "Starting visit #{ip}:#{port}#{uri}"
h = Net::HTTP.new(ip, port )
response =  h.get(uri, nil)
puts response.message

#
# test case 3
#
uri = '/cgi-bin/p1.rb'
puts "Starting visit #{ip}:#{port}#{uri}"
h = Net::HTTP.new(ip, port )
response =  h.get(uri, nil)
puts response.message

#
# test case 4
#
uri = "/a/b/c"
puts "Starting visit #{ip}:#{port}#{uri}"
h = Net::HTTP.new(ip, port )
response =  h.get(uri, nil)
puts response.message

# since ./sws is running, so app will be blocked here.
Process.waitpid(pid)

