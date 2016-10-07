# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38575 - The audit system must be configured to audit user deletions of files and programs.'

control 'V-38575' do
  impact 0.1
  title 'The audit system must be configured to audit user deletions of files and programs.'
  desc '
Auditing file deletions will create an audit trail for files that are removed from the system. The audit trail could aid in system troubleshooting, as well as detecting malicious processes that attempt to delete log files to conceal their presence.
'
  tag 'stig','V-38575'
  tag severity: 'low'
  tag checkid: 'C-46133r3_chk'
  tag fixid: 'F-43523r4_fix'
  tag version: 'RHEL-06-000200'
  tag ruleid: 'SV-50376r4_rule'
  tag fixtext: '
At a minimum, the audit system should collect file deletion events for all users and root. Add the following (or equivalent) to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system: 

-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete


'
  tag checktext: '
To determine if the system is configured to audit calls to the "rmdir" system call, run the following command:

$ sudo grep -w "rmdir" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the "unlink" system call, run the following command:

$ sudo grep -w "unlink" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the "unlinkat" system call, run the following command:

$ sudo grep -w "unlinkat" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the "rename" system call, run the following command:

$ sudo grep -w "rename" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the "renameat" system call, run the following command:

$ sudo grep -w "renameat" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line.

If no line is returned, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
