require 'pty'

version = "1.0.0"
$nocache = false

def run(command)
  lines = []
  PTY.spawn(command) do |stdin, stdout, pid|
    begin
      stdin.each do |line|
        lines << line
        puts line
      end
    rescue Errno::EIO
      # we are done
    end
  end

  lines
end


def build(path)
  lines = run("cd #{path} && docker build #{$nocache ? "--no-cache" : ""} .")
  lines[-1]["successfully built ".length..-1].strip
end

img = build("build_image")
pwd = `pwd`.strip
run "docker run --rm -it -v #{pwd}/build_image:/shared #{img}"

repo = "samsaffron/discourse-auth-proxy"
tag = "#{repo}:#{version}"
latest = "#{repo}:#{latest}"

img = build(".")
run "docker tag -f #{img} #{tag}"
run "docker tag -f #{img} #{latest}"


