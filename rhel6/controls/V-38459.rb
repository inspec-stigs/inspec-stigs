# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38459 - The /etc/group file must be group-owned by root.'

control 'V-38459' do
  impact 0.5
  title 'The /etc/group file must be group-owned by root.'
  desc '
The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.
'
  tag 'stig','V-38459'
  tag severity: 'medium'
  tag checkid: 'C-46014r1_chk'
  tag fixid: 'F-43404r1_fix'
  tag version: 'RHEL-06-000043'
  tag ruleid: 'SV-50259r1_rule'
  tag fixtext: '
To properly set the group owner of "/etc/group", run the command:

# chgrp root /etc/group
'
  tag checktext: '
To check the group ownership of "/etc/group", run the command:

$ ls -l /etc/group

If properly configured, the output should indicate the following group-owner. "root"
If it does not, this is a finding.
'

# START_DESCRIBE V-38459
  describe file('/etc/group') do
    its('group') { should eq 'root' }
  end
# END_DESCRIBE V-38459

end
