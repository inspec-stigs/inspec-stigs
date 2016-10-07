# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38680 - The audit system must identify staff members to receive notifications of audit log storage volume capacity issues.'

control 'V-38680' do
  impact 0.5
  title 'The audit system must identify staff members to receive notifications of audit log storage volume capacity issues.'
  desc '
Email sent to the root account is typically aliased to the administrators of the system, who can take appropriate action.
'
  tag 'stig','V-38680'
  tag severity: 'medium'
  tag checkid: 'C-46241r1_chk'
  tag fixid: 'F-43629r1_fix'
  tag version: 'RHEL-06-000313'
  tag ruleid: 'SV-50481r1_rule'
  tag fixtext: '
The "auditd" service can be configured to send email to a designated account in certain situations. Add or correct the following line in "/etc/audit/auditd.conf" to ensure that administrators are notified via email for those situations: 

action_mail_acct = root
'
  tag checktext: '
Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to send email to an account when it needs to notify an administrator: 

action_mail_acct = root


If auditd is not configured to send emails per identified actions, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
