# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38524 - The system must not accept ICMPv4 redirect packets on any interface.'

control 'V-38524' do
  impact 0.5
  title 'The system must not accept ICMPv4 redirect packets on any interface.'
  desc '
Accepting ICMP redirects has few legitimate uses. It should be disabled unless it is absolutely required.
'
  tag 'stig','V-38524'
  tag severity: 'medium'
  tag checkid: 'C-46082r2_chk'
  tag fixid: 'F-43472r1_fix'
  tag version: 'RHEL-06-000084'
  tag ruleid: 'SV-50325r2_rule'
  tag fixtext: '
To set the runtime status of the "net.ipv4.conf.all.accept_redirects" kernel parameter, run the following command:

# sysctl -w net.ipv4.conf.all.accept_redirects=0

If this is not the system\'s default value, add the following line to "/etc/sysctl.conf":

net.ipv4.conf.all.accept_redirects = 0
'
  tag checktext: '
The status of the "net.ipv4.conf.all.accept_redirects" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.accept_redirects

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.all.accept_redirects /etc/sysctl.conf

If the correct value is not returned, this is a finding.
'

# START_DESCRIBE V-38524
  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should eq 0 }
  end
# END_DESCRIBE V-38524

end
