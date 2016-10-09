# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38461 - The /etc/group file must have mode 0644 or less permissive.'

control 'V-38461' do
  impact 0.5
  title 'The /etc/group file must have mode 0644 or less permissive.'
  desc '
The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.
'
  tag 'stig','V-38461'
  tag severity: 'medium'
  tag checkid: 'C-46015r1_chk'
  tag fixid: 'F-43406r1_fix'
  tag version: 'RHEL-06-000044'
  tag ruleid: 'SV-50261r1_rule'
  tag fixtext: '
To properly set the permissions of "/etc/group", run the command:

# chmod 644 /etc/group
'
  tag checktext: '
To check the permissions of "/etc/group", run the command:

$ ls -l /etc/group

If properly configured, the output should indicate the following permissions: "-rw-r--r--"
If it does not, this is a finding.
'

# START_DESCRIBE V-38461
  describe file('/etc/group') do
    its('mode') { should cmp '0644' }
  end
# END_DESCRIBE V-38461

end
