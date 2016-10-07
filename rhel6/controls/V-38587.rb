# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38587 - The telnet-server package must not be installed.'

control 'V-38587' do
  impact 1.0
  title 'The telnet-server package must not be installed.'
  desc '
Removing the "telnet-server" package decreases the risk of the unencrypted telnet service\'s accidental (or intentional) activation.

Mitigation:  If the telnet-server package is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated.
'
  tag 'stig','V-38587'
  tag severity: 'high'
  tag checkid: 'C-46144r1_chk'
  tag fixid: 'F-43535r1_fix'
  tag version: 'RHEL-06-000206'
  tag ruleid: 'SV-50388r1_rule'
  tag fixtext: '
The "telnet-server" package can be uninstalled with the following command: 

# yum erase telnet-server
'
  tag checktext: '
Run the following command to determine if the "telnet-server" package is installed: 

# rpm -q telnet-server


If the package is installed, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
