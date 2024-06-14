class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Windows Server 2003 & IIS 6.0 - Remote Code Execution',
      'Description' => %q{
        Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2
        contains a buffer overflow vulnerability in the ScStoragePathFromUrl function
        in the WebDAV service that could allow remote attackers to execute arbitrary
        code via a long header beginning with "If <http://" in a PROPFIND request.
      },
      'Author'      => [
        'K3ysTr0K3R'
      ],
      'References'  => [
        ['URL', 'https://blog.0patch.com/2017/03/0patching-immortal-cve-2017-7269.html'],
        ['URL', 'https://github.com/danigargu/explodingcan/blob/master/explodingcan.py'],
        ['CVE', '2017-7269'],
        ['URL', 'https://github.com/edwardz246003/IIS_exploit'],
        ['URL', 'http://www.securitytracker.com/id/1038168']
      ],
      'DisclosureDate' => '2017-03-27',
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptInt.new('THREADS', [true, 'The number of concurrent threads', 10])
      ]
    )
  end

  def run_host(ip)
    print_status("Checking #{ip} for CVE-2017-7269 vulnerability...")

    begin
      res = send_request_cgi({
        'method' => 'OPTIONS',
        'uri'    => '/',
      })

      if res && res.code == 200
        headers = res.headers
        if headers['Public']&.include?('PROPFIND') || headers['Allow']&.include?('PROPFIND')
          print_good("#{ip} is vulnerable to CVE-2017-7269 (IIS 6.0 - WebDAV)")
          report_vuln(
            host: ip,
            name: 'CVE-2017-7269',
            refs: ['CVE-2017-7269'],
            info: 'IIS 6.0 - WebDAV RCE vulnerability'
          )
          report_note(
            host: ip,
            type: 'vulnerability',
            data: {
              name: 'CVE-2017-7269',
              description: 'IIS 6.0 - WebDAV RCE vulnerability',
              refs: ['CVE-2017-7269']
            }
          )
        else
          print_status("#{ip} is not vulnerable to CVE-2017-7269")
        end
      else
        print_error("Failed to get a response from #{ip}")
      end

    rescue ::Rex::ConnectionError, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
      print_error("Connection failed to #{ip}: #{e}")
    end
  end
end
