# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38529 - The system must not accept IPv4 source-routed packets by default.'

control 'V-38529' do
  impact 0.5
  title 'The system must not accept IPv4 source-routed packets by default.'
  desc '
Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required.
'
  tag 'stig','V-38529'
  tag severity: 'medium'
  tag checkid: 'C-46088r2_chk'
  tag fixid: 'F-43478r1_fix'
  tag version: 'RHEL-06-000089'
  tag ruleid: 'SV-50330r2_rule'
  tag fixtext: '
To set the runtime status of the "net.ipv4.conf.default.accept_source_route" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.default.accept_source_route=0

If this is not the system\'s default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.default.accept_source_route = 0
'
  tag checktext: '
The status of the "net.ipv4.conf.default.accept_source_route" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.accept_source_route

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.default.accept_source_route /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
