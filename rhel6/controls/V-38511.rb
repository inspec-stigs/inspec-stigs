# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38511 - IP forwarding for IPv4 must not be enabled, unless the system is a router.'

control 'V-38511' do
  impact 0.5
  title 'IP forwarding for IPv4 must not be enabled, unless the system is a router.'
  desc '
IP forwarding permits the kernel to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers.
'
  tag 'stig','V-38511'
  tag severity: 'medium'
  tag checkid: 'C-46068r3_chk'
  tag fixid: 'F-43458r2_fix'
  tag version: 'RHEL-06-000082'
  tag ruleid: 'SV-50312r2_rule'
  tag fixtext: '
To set the runtime status of the "net.ipv4.ip_forward" kernel parameter, run the following command: 

# sysctl -w net.ipv4.ip_forward=0

If this is not the system\'s default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.ip_forward = 0
'
  tag checktext: '
The status of the "net.ipv4.ip_forward" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.ip_forward

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.ip_forward /etc/sysctl.conf

The ability to forward packets is only appropriate for routers. If the correct value is not returned, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
