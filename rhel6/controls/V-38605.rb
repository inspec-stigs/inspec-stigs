# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38605 - The cron service must be running.'

control 'V-38605' do
  impact 0.5
  title 'The cron service must be running.'
  desc '
Due to its usage for maintenance and security-supporting tasks, enabling the cron daemon is essential.
'
  tag 'stig','V-38605'
  tag severity: 'medium'
  tag checkid: 'C-46163r1_chk'
  tag fixid: 'F-43553r2_fix'
  tag version: 'RHEL-06-000224'
  tag ruleid: 'SV-50406r2_rule'
  tag fixtext: '
The "crond" service is used to execute commands at preconfigured times. It is required by almost all systems to perform necessary maintenance tasks, such as notifying root of system activity. The "crond" service can be enabled with the following commands: 

# chkconfig crond on
# service crond start
'
  tag checktext: '
Run the following command to determine the current status of the "crond" service: 

# service crond status

If the service is enabled, it should return the following: 

crond is running...


If the service is not running, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
