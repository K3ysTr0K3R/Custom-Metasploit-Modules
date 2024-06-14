class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Hikvision Device Scanner',
      'Description' => %q{
        This module scans for Hikvision devices by requesting specific URLs and
        looking for specific keywords in the response body.
      },
      'Author'      => ['K3ysTr0K3R'],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptInt.new('THREADS', [true, 'The number of concurrent threads', 10])
      ]
    )
  end

  def run_host(ip)
    paths = [
      '/favicon.ico',
      '/doc/page/login.asp'
    ]

    found = false

    paths.each do |path|
      break if found

      res = send_request_cgi({
        'method' => 'GET',
        'uri'    => path
      })

      if res && res.body && res.body.include?('Hikvision Digital Technology')
        print_good("Hikvision device found at #{ip}")
        note = {
          host: ip,
          port: datastore['RPORT'],
          proto: 'tcp',
          sname: 'http',
          desc: 'Hikvision device detected',
          data: res.body
        }
        report_note(note)
        found = true
      end
    end
  end
end
