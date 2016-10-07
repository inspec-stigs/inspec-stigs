# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-54381 - The audit system must switch the system to single-user mode when available audit storage volume becomes dangerously low.'

control 'V-54381' do
  impact 0.5
  title 'The audit system must switch the system to single-user mode when available audit storage volume becomes dangerously low.'
  desc '
Administrators should be made aware of an inability to record audit records. If a separate partition or logical volume of adequate size is used, running low on space for audit records should never occur. 
'
  tag 'stig','V-54381'
  tag severity: 'medium'
  tag checkid: 'C-54997r2_chk'
  tag fixid: 'F-59235r2_fix'
  tag version: 'RHEL-06-000163'
  tag ruleid: 'SV-68627r1_rule'
  tag fixtext: '
The "auditd" service can be configured to take an action when disk space is running low but prior to running out of space completely. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting [ACTION] appropriately:

admin_space_left_action = [ACTION]

Set this value to "single" to cause the system to switch to single-user mode for corrective action. Acceptable values also include "suspend" and "halt". For certain systems, the need for availability outweighs the need to log all actions, and a different setting should be determined. Details regarding all possible values for [ACTION] are described in the "auditd.conf" man page. 
'
  tag checktext: '
Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to either suspend, switch to single-user mode, or halt when disk space has run low:

admin_space_left_action single

If the system is not configured to switch to single-user mode for corrective action, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
