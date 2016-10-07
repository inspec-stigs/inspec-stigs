# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38542 - The system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces.'

control 'V-38542' do
  impact 0.5
  title 'The system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces.'
  desc '
Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks.
'
  tag 'stig','V-38542'
  tag severity: 'medium'
  tag checkid: 'C-46100r2_chk'
  tag fixid: 'F-43490r1_fix'
  tag version: 'RHEL-06-000096'
  tag ruleid: 'SV-50343r2_rule'
  tag fixtext: '
To set the runtime status of the "net.ipv4.conf.all.rp_filter" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.rp_filter=1

If this is not the system\'s default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.all.rp_filter = 1
'
  tag checktext: '
The status of the "net.ipv4.conf.all.rp_filter" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.rp_filter

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.all.rp_filter /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
