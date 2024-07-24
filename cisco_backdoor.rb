class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Cisco IOS XE - Implant Detection',
      'Description' => %q{
        Cisco is aware of active exploitation of a previously unknown vulnerability
        in the web UI feature of Cisco IOS XE Software when exposed to the internet
        or to untrusted networks. This vulnerability allows a remote, unauthenticated
        attacker to create an account on an affected system with privilege level 15
        access. The attacker can then use that account to gain control of the affected system.
      },
      'Author'      => ['K3ysTr0K3R'],
      'License'     => MSF_LICENSE,
      'References'  => [
        ['URL', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z'],
        ['URL', 'https://www.bleepingcomputer.com/news/security/cisco-warns-of-new-ios-xe-zero-day-actively-exploited-in-attacks/'],
        ['URL', 'https://socradar.io/cisco-warns-of-exploitation-of-a-maximum-severity-zero-day-vulnerability-in-ios-xe-cve-2023-20198'],
        ['URL', 'https://github.com/vulncheck-oss/cisco-ios-xe-implant-scanner/blob/main/implant-scanner.go']
      ],
      'DisclosureDate' => '2023-06-01',
      'Actions'     => [
        ['Default Action', {'Description' => 'Detect Cisco IOS XE Implant'}]
      ],
      'DefaultAction' => 'Default Action'
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptInt.new('THREADS', [true, 'Number of threads', 10])
      ]
    )
  end

  def run_host(ip)
    begin
      res1 = send_request_cgi({
        'method' => 'GET',
        'uri'    => '/webui',
        'headers' => {
          'Host' => datastore['RHOST']
        }
      })

      if res1 && res1.body =~ /webui-centerpanel-title/
        res2 = send_request_cgi({
          'method' => 'POST',
          'uri'    => '/webui/logoutconfirm.html?logon_hash=1',
          'headers' => {
            'Host' => datastore['RHOST'],
            'Authorization' => '0ff4fbf0ecffa77ce8d3852a29263e263838e9bb'
          }
        })

        if res2 && res2.code == 200 && res2.body =~ /^([a-f0-9]{18})\s*$/
          implant_detected = $1
          note_data = {
            ip: ip,
            implant: implant_detected,
            description: 'Cisco IOS XE Implant Detected'
          }
          create_note(
            type: 'cisco-implant-detect',
            data: note_data,
            update: :unique_data
          )
          print_good("Implant detected on #{ip}: #{implant_detected}")
        else
          print_error("No implant detected on #{ip}.")
        end
      else
        print_error("Failed to access web UI on #{ip}.")
      end
    rescue ::Rex::ConnectionError
      print_error("Failed to connect to #{ip}.")
    end
  end
end
