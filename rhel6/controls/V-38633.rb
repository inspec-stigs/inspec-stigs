# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38633 - The system must set a maximum audit log file size.'

control 'V-38633' do
  impact 0.5
  title 'The system must set a maximum audit log file size.'
  desc '
The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained.
'
  tag 'stig','V-38633'
  tag severity: 'medium'
  tag checkid: 'C-46192r1_chk'
  tag fixid: 'F-43582r1_fix'
  tag version: 'RHEL-06-000160'
  tag ruleid: 'SV-50434r1_rule'
  tag fixtext: '
Determine the amount of audit data (in megabytes) which should be retained in each log file. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting the correct value for [STOREMB]: 

max_log_file = [STOREMB]

Set the value to "6" (MB) or higher for general-purpose systems. Larger values, of course, support retention of even more audit data.
'
  tag checktext: '
Inspect "/etc/audit/auditd.conf" and locate the following line to determine how much data the system will retain in each audit log file: "# grep max_log_file /etc/audit/auditd.conf" 

max_log_file = 6


If the system audit data threshold hasn\'t been properly set up, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
