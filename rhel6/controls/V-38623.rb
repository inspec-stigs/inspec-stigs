# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38623 - All rsyslog-generated log files must have mode 0600 or less permissive.'

control 'V-38623' do
  impact 0.5
  title 'All rsyslog-generated log files must have mode 0600 or less permissive.'
  desc '
Log files can contain valuable information regarding system configuration. If the system log files are not protected, unauthorized users could change the logged data, eliminating their forensic value.
'
  tag 'stig','V-38623'
  tag severity: 'medium'
  tag checkid: 'C-46181r2_chk'
  tag fixid: 'F-43571r1_fix'
  tag version: 'RHEL-06-000135'
  tag ruleid: 'SV-50424r2_rule'
  tag fixtext: '
The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file\'s permissions:

$ ls -l [LOGFILE]

If the permissions are not 600 or more restrictive, run the following command to correct this:

# chmod 0600 [LOGFILE]
'
  tag checktext: '
The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file\'s permissions: 

$ ls -l [LOGFILE]

The permissions should be 600, or more restrictive. Some log files referenced in /etc/rsyslog.conf may be created by other programs and may require exclusion from consideration.

If the permissions are not correct, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
