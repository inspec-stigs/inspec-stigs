# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38539 - The system must be configured to use TCP syncookies when experiencing a TCP SYN flood.'

control 'V-38539' do
  impact 0.5
  title 'The system must be configured to use TCP syncookies when experiencing a TCP SYN flood.'
  desc '
A TCP SYN flood attack can cause a denial of service by filling a system\'s TCP connection table with connections in the SYN_RCVD state. Syncookies can be used to track a connection when a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source. This feature is activated when a flood condition is detected, and enables the system to continue servicing valid connection requests.
'
  tag 'stig','V-38539'
  tag severity: 'medium'
  tag checkid: 'C-46097r2_chk'
  tag fixid: 'F-43487r1_fix'
  tag version: 'RHEL-06-000095'
  tag ruleid: 'SV-50340r2_rule'
  tag fixtext: '
To set the runtime status of the "net.ipv4.tcp_syncookies" kernel parameter, run the following command: 

# sysctl -w net.ipv4.tcp_syncookies=1

If this is not the system\'s default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.tcp_syncookies = 1
'
  tag checktext: '
The status of the "net.ipv4.tcp_syncookies" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.tcp_syncookies

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.tcp_syncookies /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
