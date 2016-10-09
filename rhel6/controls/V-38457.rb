# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38457 - The /etc/passwd file must have mode 0644 or less permissive.'

control 'V-38457' do
  impact 0.5
  title 'The /etc/passwd file must have mode 0644 or less permissive.'
  desc '
If the "/etc/passwd" file is writable by a group-owner or the world the risk of its compromise is increased. The file contains the list of accounts on the system and associated information, and protection of this file is critical for system security.
'
  tag 'stig','V-38457','passwd'
  tag severity: 'medium'
  tag checkid: 'C-46007r1_chk'
  tag fixid: 'F-43397r1_fix'
  tag version: 'RHEL-06-000041'
  tag ruleid: 'SV-50257r1_rule'
  tag fixtext: '
To properly set the permissions of "/etc/passwd", run the command:

# chmod 0644 /etc/passwd
'
  tag checktext: '
To check the permissions of "/etc/passwd", run the command:

$ ls -l /etc/passwd

If properly configured, the output should indicate the following permissions: "-rw-r--r--"
If it does not, this is a finding.
'

# START_DESCRIBE V-38457
  describe file('/etc/passwd') do
    its ('mode') { should cmp '0644' }
  end
# END_DESCRIBE V-38457

end
