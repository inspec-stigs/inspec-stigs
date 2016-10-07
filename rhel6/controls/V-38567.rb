# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38567 - The audit system must be configured to audit all use of setuid and setgid programs.'

control 'V-38567' do
  impact 0.1
  title 'The audit system must be configured to audit all use of setuid and setgid programs.'
  desc '
Privileged programs are subject to escalation-of-privilege attacks, which attempt to subvert their normal role of providing some necessary but limited capability. As such, motivation exists to monitor these programs for unusual activity.
'
  tag 'stig','V-38567'
  tag severity: 'low'
  tag checkid: 'C-46125r7_chk'
  tag fixid: 'F-43515r6_fix'
  tag version: 'RHEL-06-000198'
  tag ruleid: 'SV-50368r4_rule'
  tag fixtext: '
At a minimum, the audit system should collect the execution of privileged commands for all users and root. To find the relevant setuid / setgid programs, run the following command for each local partition [PART]:

$ sudo find [PART] -xdev -type f -perm /6000 2>/dev/null

Then, for each setuid / setgid program on the system, add a line of the following form to "/etc/audit/audit.rules", where [SETUID_PROG_PATH] is the full path to each setuid / setgid program in the list:

-a always,exit -F path=[SETUID_PROG_PATH] -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
'
  tag checktext: '
To verify that auditing of privileged command use is configured, run the following command once for each local partition [PART] to find relevant setuid / setgid programs:

$ sudo find [PART] -xdev -type f -perm /6000 2>/dev/null

Run the following command to verify entries in the audit rules for all programs found with the previous command:

$ sudo grep path /etc/audit/audit.rules

It should be the case that all relevant setuid / setgid programs have a line in the audit rules. If that is not the case, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
