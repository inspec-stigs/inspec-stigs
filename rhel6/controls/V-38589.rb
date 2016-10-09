# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38589 - The telnet daemon must not be running.'

control 'V-38589' do
  impact 1.0
  title 'The telnet daemon must not be running.'
  desc '
The telnet protocol uses unencrypted network communication, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network. The telnet protocol is also subject to man-in-the-middle attacks.

Mitigation:  If an enabled telnet daemon is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated.
'
  tag 'stig','V-38589'
  tag severity: 'high'
  tag checkid: 'C-46147r3_chk'
  tag fixid: 'F-43537r1_fix'
  tag version: 'RHEL-06-000211'
  tag ruleid: 'SV-50390r2_rule'
  tag fixtext: '
The "telnet" service can be disabled with the following command:

# chkconfig telnet off
'
  tag checktext: '
To check that the "telnet" service is disabled in system boot configuration, run the following command:

# chkconfig "telnet" --list

Output should indicate the "telnet" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig "telnet" --list
telnet         off
OR
error reading information on service telnet: No such file or directory


If the service is running, this is a finding.
'

# START_DESCRIBE V-38589
  describe service('telnet') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
# END_DESCRIBE V-38589

end
