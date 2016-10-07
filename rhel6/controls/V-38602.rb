# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38602 - The rlogind service must not be running.'

control 'V-38602' do
  impact 1.0
  title 'The rlogind service must not be running.'
  desc '
The rlogin service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network.
'
  tag 'stig','V-38602'
  tag severity: 'high'
  tag checkid: 'C-46158r3_chk'
  tag fixid: 'F-43549r3_fix'
  tag version: 'RHEL-06-000218'
  tag ruleid: 'SV-50403r2_rule'
  tag fixtext: '
The "rlogin" service, which is available with the "rsh-server" package and runs as a service through xinetd, should be disabled. The "rlogin" service can be disabled with the following command: 

# chkconfig rlogin off
'
  tag checktext: '
 
To check that the "rlogin" service is disabled in system boot configuration, run the following command:

# chkconfig "rlogin" --list

Output should indicate the "rlogin" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig "rlogin" --list
rlogin off
OR
error reading information on service rlogin: No such file or directory


If the service is running, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
