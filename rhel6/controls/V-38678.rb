# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38678 - The audit system must provide a warning when allocated audit record storage volume reaches a documented percentage of maximum audit record storage capacity.'

control 'V-38678' do
  impact 0.5
  title 'The audit system must provide a warning when allocated audit record storage volume reaches a documented percentage of maximum audit record storage capacity.'
  desc '
Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption.
'
  tag 'stig','V-38678'
  tag severity: 'medium'
  tag checkid: 'C-46240r1_chk'
  tag fixid: 'F-43627r2_fix'
  tag version: 'RHEL-06-000311'
  tag ruleid: 'SV-50479r2_rule'
  tag fixtext: '
The "auditd" service can be configured to take an action when disk space starts to run low. Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [num_megabytes] appropriately:

space_left = [num_megabytes]

The "num_megabytes" value should be set to a fraction of the total audit storage capacity available that will allow a system administrator to be notified with enough time to respond to the situation causing the capacity issues.  This value must also be documented locally.
'
  tag checktext: '
Inspect "/etc/audit/auditd.conf" and locate the following line to determine whether the system is configured to email the administrator when disk space is starting to run low:

# grep space_left /etc/audit/auditd.conf

space_left = [num_megabytes]


If the "num_megabytes" value does not correspond to a documented value for remaining audit partition capacity or if there is no locally documented value for remaining audit partition capacity, this is a finding.
'

# START_DESCRIBE V-38678
  tag 'auditd','auditd.conf','space_left'
  describe parse_config_file('/etc/audit/auditd.conf') do
    its('space_left') { should match /[0-9]/ }
  end
# END_DESCRIBE V-38678

end
