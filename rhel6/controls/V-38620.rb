# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38620 - The system clock must be synchronized continuously, or at least daily.'

control 'V-38620' do
  impact 0.5
  title 'The system clock must be synchronized continuously, or at least daily.'
  desc '
Enabling the "ntpd" service ensures that the "ntpd" service will be running and that the system will synchronize its time to any servers specified. This is important whether the system is configured to be a client (and synchronize only its own clock) or it is also acting as an NTP server to other systems. Synchronizing time is essential for authentication services such as Kerberos, but it is also important for maintaining accurate logs and auditing possible security breaches.
'
  tag 'stig','V-38620'
  tag severity: 'medium'
  tag checkid: 'C-46178r1_chk'
  tag fixid: 'F-43568r1_fix'
  tag version: 'RHEL-06-000247'
  tag ruleid: 'SV-50421r1_rule'
  tag fixtext: '
The "ntpd" service can be enabled with the following command: 

# chkconfig ntpd on
# service ntpd start
'
  tag checktext: '
Run the following command to determine the current status of the "ntpd" service: 

# service ntpd status

If the service is enabled, it should return the following: 

ntpd is running...


If the service is not running, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
