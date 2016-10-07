# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38470 - The audit system must alert designated staff members when the audit storage volume approaches capacity.'

control 'V-38470' do
  impact 0.5
  title 'The audit system must alert designated staff members when the audit storage volume approaches capacity.'
  desc '
Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption.
'
  tag 'stig','V-38470'
  tag severity: 'medium'
  tag checkid: 'C-46025r3_chk'
  tag fixid: 'F-43415r2_fix'
  tag version: 'RHEL-06-000005'
  tag ruleid: 'SV-50270r2_rule'
  tag fixtext: '
The "auditd" service can be configured to take an action when disk space starts to run low. Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [ACTION] appropriately: 

space_left_action = [ACTION]

Possible values for [ACTION] are described in the "auditd.conf" man page. These include: 

"ignore"
"syslog"
"email"
"exec"
"suspend"
"single"
"halt"


Set this to "email" (instead of the default, which is "suspend") as it is more likely to get prompt attention.  The "syslog" option is acceptable, provided the local log management infrastructure notifies an appropriate administrator in a timely manner.

RHEL-06-000521 ensures that the email generated through the operation "space_left_action" will be sent to an administrator.
'
  tag checktext: '
Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to email the administrator when disk space is starting to run low: 

# grep space_left_action /etc/audit/auditd.conf
space_left_action = email


If the system is not configured to send an email to the system administrator when disk space is starting to run low, this is a finding.  The "syslog" option is acceptable when it can be demonstrated that the local log management infrastructure notifies an appropriate administrator in a timely manner.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
