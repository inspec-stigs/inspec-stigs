# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38528 - The system must log Martian packets.'

control 'V-38528' do
  impact 0.1
  title 'The system must log Martian packets.'
  desc '
The presence of "martian" packets (which have impossible addresses) as well as spoofed packets, source-routed packets, and redirects could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.
'
  tag 'stig','V-38528'
  tag severity: 'low'
  tag checkid: 'C-46086r3_chk'
  tag fixid: 'F-43476r1_fix'
  tag version: 'RHEL-06-000088'
  tag ruleid: 'SV-50329r2_rule'
  tag fixtext: '
To set the runtime status of the "net.ipv4.conf.all.log_martians" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.log_martians=1

If this is not the system\'s default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.all.log_martians = 1
'
  tag checktext: '
The status of the "net.ipv4.conf.all.log_martians" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.log_martians

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.all.log_martians /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
