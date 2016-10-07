# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38609 - The TFTP service must not be running.'

control 'V-38609' do
  impact 0.5
  title 'The TFTP service must not be running.'
  desc '
Disabling the "tftp" service ensures the system is not acting as a tftp server, which does not provide encryption or authentication.
'
  tag 'stig','V-38609'
  tag severity: 'medium'
  tag checkid: 'C-46166r2_chk'
  tag fixid: 'F-43557r4_fix'
  tag version: 'RHEL-06-000223'
  tag ruleid: 'SV-50410r2_rule'
  tag fixtext: '
The "tftp" service should be disabled. The "tftp" service can be disabled with the following command: 

# chkconfig tftp off
'
  tag checktext: '
To check that the "tftp" service is disabled in system boot configuration, run the following command:

# chkconfig "tftp" --list

Output should indicate the "tftp" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig "tftp" --list
tftp off
OR
error reading information on service tftp: No such file or directory


If the service is running, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
